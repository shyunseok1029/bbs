var express = require('express');
var router = express.Router();
var oracledb = require('oracledb');
var passwords = require('../lib/password');
var upload = require('../lib/upload');
var path = require('path');
var fs = require('fs');

oracledb.autoCommit = true;

var dbconfig = require('../config').db;

var CONTENT_MAX_BYTES = 4000;

function utf8ByteLength(value) {
  return Buffer.byteLength(value || '', 'utf8');
}

function isBlank(value) {
  return !value || value.trim() === '';
}

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value || '');
}

function runQuery(sql, binds, callback) {
  oracledb.getConnection(dbconfig, function(err, connection) {
    if (err) {
      callback(err);
      return;
    }

    connection.execute(sql, binds || [], function(execErr, result) {
      connection.release();
      callback(execErr, result);
    });
  });
}

function renderError(res, code) {
  res.render('bbs/error', { errcode: code });
}

function requireLogin(req, res, code) {
  if (req.session.user) return true;
  res.status(401);
  renderError(res, code);
  return false;
}

function checkPostOwner(req, res, brdno, callback) {
  if (!requireLogin(req, res, 4)) return;

  var sql = 'SELECT WRITER FROM BBS WHERE NO = :brdno';
  runQuery(sql, { brdno: brdno }, function(err, result) {
    if (err || !result.rows || result.rows.length < 1) {
      res.redirect('/bbs/list');
      return;
    }

    if (result.rows[0][0] !== req.session.user.id) {
      res.status(403);
      renderError(res, 7);
      return;
    }

    callback();
  });
}

router.get('/', function(req, res) {
  res.redirect('/bbs/list');
});

router.get('/login', function(req, res) {
  res.render('bbs/login', { errcode: req.session.user ? 3 : 0 });
});

router.post('/logout', function(req, res) {
  if (!req.session.user) return res.redirect('/bbs/list');
  req.session.destroy(function(err) {
    if (err) return res.status(500).send('로그아웃 처리 중 오류가 발생했습니다.');
    res.clearCookie('connect.sid');
    res.redirect('/bbs/list');
  });
});

router.get('/findid', function(req, res) {
  res.render('bbs/findid', { result: null, searched: false });
});

router.post('/findidsave', function(req, res) {
  var sql = 'SELECT ID FROM LOGIN WHERE NAME = :name AND EMAIL = :email AND NVL(OK, 1) = 1';
  runQuery(sql, {
    name: req.body.name,
    email: req.body.email
  }, function(err, result) {
    if (err) console.error('요청 처리 중 오류가 발생했습니다.');
    res.render('bbs/findid', {
      result: result && result.rows && result.rows.length > 0 ? result.rows[0][0] : null,
      searched: true
    });
  });
});

// Recovery requires a verified out-of-band channel; disable until one exists.
router.all(['/findpw', '/findpwcheck', '/resetpwsave'], function(req, res) {
  res.status(503).send('안전한 계정 복구 기능을 준비 중입니다.');
});

router.get('/signup', function(req, res) {
  res.render('bbs/signup', { code: req.session.user ? 1 : 0 });
});

router.get('/checkid', function(req, res) {
  var id = req.query.id || '';

  if (id.length < 4 || id.length > 20) {
    res.json({ available: false, message: '아이디는 4~20자로 입력하세요.' });
    return;
  }

  var sql = 'SELECT COUNT(*) FROM LOGIN WHERE ID = :id';
  runQuery(sql, { id: id }, function(err, result) {
    if (err) {
      res.json({ available: false, message: '아이디 확인 중 오류가 발생했습니다.' });
      return;
    }

    var count = parseInt(result.rows[0][0], 10);
    if (count > 0) {
      res.json({ available: false, message: '이미 사용 중인 아이디입니다.' });
      return;
    }

    res.json({ available: true, message: '사용 가능한 아이디입니다.' });
  });
});

router.post('/signupsave', function(req, res) {
  var id = req.body.id;
  var pw1 = req.body.pw1;
  var pw2 = req.body.pw2;
  var name = req.body.name;
  var email = req.body.email;

  if (pw1 !== pw2) {
    renderError(res, 1);
    return;
  }
  if (isBlank(id) || isBlank(pw1) || isBlank(name) || isBlank(email)) {
    renderError(res, 2);
    return;
  }
  if (id.length < 4 || id.length > 20 || pw1.length < 6 || pw1.length > 20 || !isValidEmail(email)) {
    renderError(res, 12);
    return;
  }

  var checkSql = 'SELECT COUNT(*) FROM LOGIN WHERE ID = :id';
  runQuery(checkSql, { id: id }, function(checkErr, checkResult) {
    if (checkErr) {
      renderError(res, 3);
      return;
    }

    if (parseInt(checkResult.rows[0][0], 10) > 0) {
      renderError(res, 3);
      return;
    }

    var salt = null;
    var hashPassword = passwords.hash(pw1);
    var sql = 'INSERT INTO LOGIN(ID, PASSWORD, NAME, EMAIL, SALT) VALUES(:id, :password, :name, :email, :salt)';

    runQuery(sql, { id: id, password: hashPassword, name: name, email: email, salt: salt }, function(err) {
      if (err) {
        renderError(res, 3);
        return;
      }
      res.redirect('/bbs/login');
    });
  });
});

router.get('/updatesignup', function(req, res) {
  if (!requireLogin(req, res, 4)) return;

  var sql = 'SELECT ID, NAME, EMAIL FROM LOGIN WHERE ID = :id';
  runQuery(sql, { id: req.session.user.id }, function(err, rows) {
    if (err) {
      renderError(res, 4);
      return;
    }
    res.render('bbs/updatesignform', rows);
  });
});

router.post('/updatesignsave', function(req, res) {
  if (!requireLogin(req, res, 4)) return;

  var pw1 = req.body.pw1 || '';
  var pw2 = req.body.pw2 || '';

  if (pw1 || pw2) {
    if (pw1 !== pw2) {
      renderError(res, 1);
      return;
    }

    if (pw1.length < 6 || pw1.length > 20) return renderError(res, 12);
    var id = req.session.user.id;
    runQuery('SELECT PASSWORD, SALT FROM LOGIN WHERE ID = :id', {id: id}, function(err, result) {
      if (err || !result.rows || !result.rows.length || !passwords.verify(req.body.currentPassword, result.rows[0][0], result.rows[0][1])) {
        return res.status(403).send('현재 비밀번호를 확인하세요.');
      }
      var passwordSql = 'UPDATE LOGIN SET PASSWORD = :password, SALT = :salt, NAME = :name, EMAIL = :email WHERE ID = :id';
      runQuery(passwordSql, {id: id, password: passwords.hash(pw1), salt: null,
        name: req.body.name, email: req.body.email}, function(updateErr) {
        if (updateErr) return res.status(500).send('정보 수정에 실패했습니다.');
        res.redirect('/bbs/list');
      });
    });
    return;
  }

  var sql = 'UPDATE LOGIN SET NAME = :name, EMAIL = :email WHERE ID = :id';
  runQuery(sql, {
    id: req.session.user.id,
    name: req.body.name,
    email: req.body.email
  }, function(err) {
    if (err) console.error('요청 처리 중 오류가 발생했습니다.');
    res.redirect('/bbs/list');
  });
});

router.post('/logincheck', function(req, res) {
  var id = req.body.id;
  var pw = req.body.password;
  var sql = 'SELECT OK, PASSWORD, SALT FROM LOGIN WHERE ID = :id';

  runQuery(sql, { id: id }, function(err, result) {
    if (err || !result.rows || result.rows.length < 1) {
      res.render('bbs/login', { errcode: 1 });
      return;
    }

    if (result.rows[0][0] === 0) return res.render('bbs/login', { errcode: 1 });
    var dbHashPassword = result.rows[0][1];
    var dbSalt = result.rows[0][2];
    if (!passwords.verify(pw, dbHashPassword, dbSalt)) {
      res.render('bbs/login', { errcode: 2 });
      return;
    }

    req.session.regenerate(function(regenErr) {
      if (regenErr) return res.status(500).send('로그인 처리 중 오류가 발생했습니다.');
      req.session.user = { id: id, authorized: true };
      res.redirect('/bbs/list');
    });
  });
});

function countRecord(callback) {
  runQuery('SELECT COUNT(*) FROM BBS WHERE NVL(OK, 1) = 1', [], function(err, result) {
    if (err) {
      callback(err);
      return;
    }
    callback(null, parseInt(result.rows[0][0], 10));
  });
}

function getPostOrderSql(sort) {
  if (sort === 'views') return 'VIEW_COUNT DESC, NO DESC';
  if (sort === 'likes') return 'GOOD_COUNT DESC, NO DESC';
  return 'NO DESC';
}

function getPostListSelectSql(whereSql, orderSql) {
  return 'SELECT * FROM (' +
         'SELECT NO, TITLE, WRITER, CONTENT, to_char(REGDATE, \'yyyy-mm-dd hh24:mi:ss\') AS REGDATE_TEXT, OK, COUNT AS VIEW_COUNT, ' +
         '(SELECT COUNT(*) FROM BBSW W WHERE W.BBS_NO = BBS.NO AND NVL(W.OK, 1) = 1) AS COMMENT_COUNT, ' +
         '(SELECT COUNT(*) FROM BBS_REACTION R WHERE R.BBS_NO = BBS.NO AND R.REACTION = \'GOOD\') AS GOOD_COUNT, ' +
         '(SELECT COUNT(*) FROM BBS_REACTION R WHERE R.BBS_NO = BBS.NO AND R.REACTION = \'BAD\') AS BAD_COUNT ' +
         'FROM BBS ' + whereSql +
         ') ORDER BY ' + orderSql + ' OFFSET :offset ROWS FETCH NEXT :pageSize ROWS ONLY';
}

router.get('/list', function(req, res) {
  var currentPage = req.query.currentPage ? parseInt(req.query.currentPage, 10) : 1;
  var blockSize = 5;
  var pageSize = 5;
  var sort = req.query.sort || 'latest';
  var orderSql = getPostOrderSql(sort);

  countRecord(function(err, totalRecords) {
    if (err) {
      res.render('bbs/list', emptyListData(currentPage, pageSize, blockSize, req, sort));
      return;
    }

    var totalPage = Math.ceil(totalRecords / pageSize);
    var stNum = (currentPage - 1) * pageSize;
    var sql = getPostListSelectSql('WHERE NVL(OK, 1) = 1', orderSql);

    runQuery(sql, { offset: stNum, pageSize: pageSize }, function(queryErr, rows) {
      if (queryErr) console.error('요청 처리 중 오류가 발생했습니다.');
      res.render('bbs/list', {
        data: rows || { rows: [] },
        currentPage: currentPage,
        totalRecords: totalRecords,
        pageSize: pageSize,
        totalPage: totalPage,
        blockSize: blockSize,
        firstPage: 1,
        lastPage: totalPage,
        stNum: stNum,
        userId: req.session.user ? req.session.user.id : null,
        searchChoice: '',
        searchKeyword: '',
        sort: sort
      });
    });
  });
});

function emptyListData(currentPage, pageSize, blockSize, req, sort) {
  return {
    data: { rows: [] },
    currentPage: currentPage,
    totalRecords: 0,
    pageSize: pageSize,
    totalPage: 0,
    blockSize: blockSize,
    firstPage: 1,
    lastPage: 0,
    stNum: 0,
    userId: req && req.session.user ? req.session.user.id : null,
    searchChoice: '',
    searchKeyword: '',
    sort: sort || 'latest'
  };
}

router.post('/read_count', function(req, res) {
  var sql = 'UPDATE BBS SET COUNT = NVL(COUNT, 0) + 1 WHERE NO = :brdno';
  runQuery(sql, { brdno: req.query.brdno }, function(err) {
    if (err) console.error('요청 처리 중 오류가 발생했습니다.');
    res.redirect('/bbs/read?brdno=' + req.query.brdno);
  });
});

router.get('/my', function(req, res) {
  if (!requireLogin(req, res, 4)) return;

  var postSql = 'SELECT NO, TITLE, CONTENT, to_char(REGDATE, \'yyyy-mm-dd hh24:mi:ss\'), COUNT ' +
                'FROM BBS WHERE WRITER = :writer AND NVL(OK, 1) = 1 ORDER BY NO DESC';
  runQuery(postSql, { writer: req.session.user.id }, function(postErr, posts) {
    if (postErr) console.error('요청 처리 중 오류가 발생했습니다.');

    var commentSql = 'SELECT W.NO, W.BBS_NO, B.TITLE, W.CONTENT, to_char(W.REGDATE, \'yyyy-mm-dd hh24:mi:ss\'), W.PARENT_NO ' +
                     'FROM BBSW W JOIN BBS B ON W.BBS_NO = B.NO ' +
                     'WHERE W.WRITER = :writer AND NVL(W.OK, 1) = 1 AND NVL(B.OK, 1) = 1 ' +
                     'ORDER BY W.NO DESC';

    runQuery(commentSql, { writer: req.session.user.id }, function(commentErr, comments) {
      if (commentErr) console.error('요청 처리 중 오류가 발생했습니다.');
      res.render('bbs/my', {
        posts: posts || { rows: [] },
        comments: comments || { rows: [] },
        userId: req.session.user.id
      });
    });
  });
});

router.get('/form', function(req, res) {
  if (!requireLogin(req, res, 6)) return;
  res.render('bbs/form', { id: req.session.user.id });
});

router.post('/save', function(req, res) {
  if (!requireLogin(req, res, 6)) return;
  var content = req.body.brdmemo || '', title = req.body.brdtitle || '';
  if (isBlank(title) || isBlank(content)) return renderError(res, 10);
  if (utf8ByteLength(content) > CONTENT_MAX_BYTES) return renderError(res, 8);
  if (!upload.validate(req.file)) return res.status(400).send('허용되지 않는 첨부파일입니다.');
  var file;
  try { file = upload.save(req.file); } catch (err) { return res.status(500).send('첨부파일 저장에 실패했습니다.'); }
  var sql = 'INSERT INTO BBS(NO, TITLE, CONTENT, WRITER, REGDATE, FILENAME, ORIGINAL_FILENAME) ' +
            'VALUES(bbs_seq.nextval, :title, :content, :writer, sysdate, :filename, :originalFilename)';
  runQuery(sql, {title: title, content: content, writer: req.session.user.id,
    filename: file ? file.filename : null, originalFilename: file ? file.originalname : null}, function(err) {
    if (err) { if (file) upload.remove(file.filename); return res.status(500).send('게시글 저장에 실패했습니다.'); }
    res.redirect('/bbs/list');
  });
});

function readBbs(brdno, callback) {
  var sql = 'SELECT NO, TITLE, WRITER, CONTENT, to_char(REGDATE, \'yyyy-mm-dd\'), OK, COUNT, ' +
            '(SELECT COUNT(*) FROM BBS_REACTION R WHERE R.BBS_NO = BBS.NO AND R.REACTION = \'GOOD\') AS GOOD_COUNT, ' +
            '(SELECT COUNT(*) FROM BBS_REACTION R WHERE R.BBS_NO = BBS.NO AND R.REACTION = \'BAD\') AS BAD_COUNT, ' +
            'FILENAME, ORIGINAL_FILENAME ' +
            'FROM BBS WHERE NO = :brdno AND NVL(OK, 1) = 1';
  runQuery(sql, { brdno: brdno }, callback);
}

function readPostReaction(brdno, userId, callback) {
  if (!userId) {
    callback(null, null);
    return;
  }

  var sql = 'SELECT REACTION FROM BBS_REACTION WHERE BBS_NO = :brdno AND USER_ID = :userId';
  runQuery(sql, { brdno: brdno, userId: userId }, function(err, result) {
    if (err || !result.rows || result.rows.length < 1) {
      callback(err, null);
      return;
    }
    callback(null, result.rows[0][0]);
  });
}

router.get('/read', function(req, res) {
  readBbs(req.query.brdno, function(err, retBBS) {
    if (err || !retBBS.rows || retBBS.rows.length < 1) {
      res.redirect('/bbs/list');
      return;
    }

    var userId = req.session.user ? req.session.user.id : null;
    var sql = 'SELECT NO, BBS_NO, WRITER, CONTENT, to_char(REGDATE, \'yyyy-mm-dd\'), ' +
              '(SELECT COUNT(*) FROM BBSW_REACTION R WHERE R.WNO = BBSW.NO AND R.REACTION = \'GOOD\') AS GOOD_COUNT, ' +
              '(SELECT COUNT(*) FROM BBSW_REACTION R WHERE R.WNO = BBSW.NO AND R.REACTION = \'BAD\') AS BAD_COUNT, ' +
              'OK, PARENT_NO, ' +
              '(SELECT R.REACTION FROM BBSW_REACTION R WHERE R.WNO = BBSW.NO AND R.USER_ID = :userId) AS MY_REACTION ' +
              'FROM BBSW WHERE BBS_NO = :brdno AND NVL(OK, 1) = 1 ' +
              'ORDER BY NVL(PARENT_NO, NO) DESC, CASE WHEN PARENT_NO IS NULL THEN 0 ELSE 1 END, NO ASC';

    runQuery(sql, { brdno: req.query.brdno, userId: userId }, function(queryErr, rows) {
      if (queryErr) console.error('요청 처리 중 오류가 발생했습니다.');

      readPostReaction(req.query.brdno, userId, function(reactionErr, postReaction) {
        if (reactionErr) console.error('요청 처리 중 오류가 발생했습니다.');
        res.render('bbs/read', {
          bbs: retBBS,
          wbbs: rows || { rows: [] },
          userId: userId,
          postReaction: postReaction
        });
      });
    });
  });
});

router.post('/wsave', function(req, res) {
  var bbsno = req.body.bbsno;
  var parentNo = req.body.parent_no || null;
  if (!requireLogin(req, res, 5)) return;
  if (isBlank(req.body.wbrdmemo)) {
    renderError(res, 11);
    return;
  }

  var sql = 'INSERT INTO BBSW(NO, BBS_NO, WRITER, CONTENT, REGDATE, PARENT_NO) ' +
            'VALUES(bbsw_seq.nextval, :bbsno, :writer, :content, sysdate, :parentNo)';

  runQuery(sql, {
    bbsno: bbsno,
    writer: req.session.user.id,
    content: req.body.wbrdmemo,
    parentNo: parentNo
  }, function(err) {
    if (err) console.error('요청 처리 중 오류가 발생했습니다.');
    res.redirect('/bbs/read?brdno=' + bbsno);
  });
});

router.post('/good', function(req, res) {
  setPostReaction(req, res, 'GOOD');
});

router.post('/bad', function(req, res) {
  setPostReaction(req, res, 'BAD');
});

function setPostReaction(req, res, reaction) {
  if (!requireLogin(req, res, 5)) return;

  var lookupBinds = {
    brdno: req.query.brdno,
    userId: req.session.user.id
  };
  var redirectUrl = '/bbs/read?brdno=' + req.query.brdno;

  var selectSql = 'SELECT REACTION FROM BBS_REACTION WHERE BBS_NO = :brdno AND USER_ID = :userId';
  runQuery(selectSql, lookupBinds, function(selectErr, result) {
    if (selectErr) {
      console.error('요청 처리 중 오류가 발생했습니다.');
      res.redirect(redirectUrl);
      return;
    }

    if (result.rows && result.rows.length > 0 && result.rows[0][0] === reaction) {
      var deleteSql = 'DELETE FROM BBS_REACTION WHERE BBS_NO = :brdno AND USER_ID = :userId';
      runQuery(deleteSql, lookupBinds, function(deleteErr) {
        if (deleteErr) console.error('요청 처리 중 오류가 발생했습니다.');
        res.redirect(redirectUrl);
      });
      return;
    }

    if (result.rows && result.rows.length > 0) {
      var updateSql = 'UPDATE BBS_REACTION SET REACTION = :reaction, REGDATE = sysdate WHERE BBS_NO = :brdno AND USER_ID = :userId';
      runQuery(updateSql, {
        brdno: req.query.brdno,
        userId: req.session.user.id,
        reaction: reaction
      }, function(updateErr) {
        if (updateErr) console.error('요청 처리 중 오류가 발생했습니다.');
        res.redirect(redirectUrl);
      });
      return;
    }

    var insertSql = 'INSERT INTO BBS_REACTION(BBS_NO, USER_ID, REACTION, REGDATE) VALUES(:brdno, :userId, :reaction, sysdate)';
    runQuery(insertSql, {
      brdno: req.query.brdno,
      userId: req.session.user.id,
      reaction: reaction
    }, function(insertErr) {
      if (insertErr) console.error('요청 처리 중 오류가 발생했습니다.');
      res.redirect(redirectUrl);
    });
  });
}

router.post('/wgood', function(req, res) {
  setCommentReaction(req, res, 'GOOD');
});

router.post('/wbad', function(req, res) {
  setCommentReaction(req, res, 'BAD');
});

function setCommentReaction(req, res, reaction) {
  if (!requireLogin(req, res, 5)) return;

  var lookupBinds = {
    wno: req.query.wno,
    userId: req.session.user.id
  };
  var redirectUrl = '/bbs/read?brdno=' + req.query.brdno + '#comment-' + req.query.wno;

  var selectSql = 'SELECT REACTION FROM BBSW_REACTION WHERE WNO = :wno AND USER_ID = :userId';
  runQuery(selectSql, lookupBinds, function(selectErr, result) {
    if (selectErr) {
      console.error('요청 처리 중 오류가 발생했습니다.');
      res.redirect(redirectUrl);
      return;
    }

    if (result.rows && result.rows.length > 0 && result.rows[0][0] === reaction) {
      var deleteSql = 'DELETE FROM BBSW_REACTION WHERE WNO = :wno AND USER_ID = :userId';
      runQuery(deleteSql, lookupBinds, function(deleteErr) {
        if (deleteErr) console.error('요청 처리 중 오류가 발생했습니다.');
        res.redirect(redirectUrl);
      });
      return;
    }

    if (result.rows && result.rows.length > 0) {
      var updateSql = 'UPDATE BBSW_REACTION SET REACTION = :reaction, REGDATE = sysdate WHERE WNO = :wno AND USER_ID = :userId';
      runQuery(updateSql, {
        wno: req.query.wno,
        userId: req.session.user.id,
        reaction: reaction
      }, function(updateErr) {
        if (updateErr) console.error('요청 처리 중 오류가 발생했습니다.');
        res.redirect(redirectUrl);
      });
      return;
    }

    var insertSql = 'INSERT INTO BBSW_REACTION(WNO, USER_ID, REACTION, REGDATE) VALUES(:wno, :userId, :reaction, sysdate)';
    runQuery(insertSql, {
      wno: req.query.wno,
      userId: req.session.user.id,
      reaction: reaction
    }, function(insertErr) {
      if (insertErr) console.error('요청 처리 중 오류가 발생했습니다.');
      res.redirect(redirectUrl);
    });
  });
}

router.post('/w_delete', function(req, res) {
  if (!requireLogin(req, res, 5)) return;

  var sql = 'UPDATE BBSW SET OK = 0 WHERE NO = :wno AND WRITER = :writer';
  runQuery(sql, {
    wno: req.query.wno,
    writer: req.session.user.id
  }, function(err) {
    if (err) console.error('요청 처리 중 오류가 발생했습니다.');
    res.redirect('/bbs/read?brdno=' + req.query.brdno);
  });
});

router.post('/w_update', function(req, res) {
  if (!requireLogin(req, res, 5)) return;
  if (isBlank(req.body.wbrdmemo)) {
    renderError(res, 11);
    return;
  }

  var brdno = req.body.brdno || req.body.bbsno;
  var sql = 'UPDATE BBSW SET CONTENT = :content WHERE NO = :wno AND WRITER = :writer';
  runQuery(sql, {
    content: req.body.wbrdmemo,
    wno: req.body.wno,
    writer: req.session.user.id
  }, function(err) {
    if (err) console.error('요청 처리 중 오류가 발생했습니다.');
    res.redirect('/bbs/read?brdno=' + brdno + '#comment-' + req.body.wno);
  });
});

router.post('/delete', function(req, res) {
  checkPostOwner(req, res, req.query.brdno, function() {
    var sql = 'UPDATE BBS SET OK = 0 WHERE NO = :brdno AND WRITER = :writer';
    runQuery(sql, { brdno: req.query.brdno, writer: req.session.user.id }, function(err) {
      if (err) console.error('요청 처리 중 오류가 발생했습니다.');
      res.redirect('/bbs/list');
    });
  });
});

router.get('/update', function(req, res) {
  checkPostOwner(req, res, req.query.brdno, function() {
    var sql = 'SELECT NO, TITLE, CONTENT, WRITER, to_char(REGDATE, \'yyyy-mm-dd\'), FILENAME, ORIGINAL_FILENAME ' +
              'FROM BBS WHERE NO = :brdno';
    runQuery(sql, { brdno: req.query.brdno }, function(err, rows) {
      if (err) console.error('요청 처리 중 오류가 발생했습니다.');
      res.render('bbs/updateform', rows || { rows: [] });
    });
  });
});

router.post('/updatesave', function(req, res) {
  if (!requireLogin(req, res, 6)) return;
  var brdno = req.body.brdno;
  checkPostOwner(req, res, brdno, function() {
    var title = req.body.brdtitle || '', content = req.body.brdmemo || '';
    if (isBlank(title) || isBlank(content)) return renderError(res, 10);
    if (utf8ByteLength(content) > CONTENT_MAX_BYTES) return renderError(res, 8);
    if (!upload.validate(req.file)) return res.status(400).send('허용되지 않는 첨부파일입니다.');
    runQuery('SELECT FILENAME, ORIGINAL_FILENAME FROM BBS WHERE NO = :brdno AND WRITER = :writer',
      {brdno: brdno, writer: req.session.user.id}, function(err, result) {
      if (err || !result.rows || !result.rows.length) return res.status(404).send('게시글을 찾을 수 없습니다.');
      var oldFilename = result.rows[0][0], oldOriginal = result.rows[0][1];
      var file;
      try { file = upload.save(req.file); } catch (error) { return res.status(500).send('첨부파일 저장에 실패했습니다.'); }
      var removeOld = !!file || req.body.deleteFile === 'Y';
      var filename = file ? file.filename : (removeOld ? null : oldFilename);
      var original = file ? file.originalname : (removeOld ? null : oldOriginal);
      var sql = 'UPDATE BBS SET TITLE = :title, CONTENT = :content, FILENAME = :filename, ORIGINAL_FILENAME = :originalFilename WHERE NO = :brdno AND WRITER = :writer';
      runQuery(sql, {title: title, content: content, filename: filename, originalFilename: original,
        writer: req.session.user.id, brdno: brdno}, function(updateErr, updateResult) {
        if (updateErr || !updateResult || updateResult.rowsAffected !== 1) {
          if (file) upload.remove(file.filename);
          return res.status(500).send('게시글 수정에 실패했습니다.');
        }
        if (removeOld) upload.remove(oldFilename);
        res.redirect('/bbs/read?brdno=' + encodeURIComponent(brdno));
      });
    });
  });
});

router.get('/attachment/:brdno', function(req, res) {
  runQuery('SELECT FILENAME, ORIGINAL_FILENAME FROM BBS WHERE NO = :brdno AND NVL(OK, 1) = 1',
    {brdno: req.params.brdno}, function(err, result) {
      if (err || !result.rows || !result.rows.length) return res.sendStatus(404);
      var name = result.rows[0][0];
      if (typeof name !== 'string' || !/^[a-f0-9]{48}\.(?:png|jpe?g|pdf|txt)$/.test(name)) return res.sendStatus(404);
      res.set('X-Content-Type-Options', 'nosniff');
      res.download(path.join(upload.directory, name), result.rows[0][1] || name, function(downloadErr) {
        if (downloadErr && !res.headersSent) res.sendStatus(404);
      });
    });
});

router.get('/search', function(req, res) {
  var choice = req.query.choice;
  var keyword = req.query.search || '';
  var search = '%' + keyword + '%';
  var currentPage = req.query.currentPage ? parseInt(req.query.currentPage, 10) : 1;
  var pageSize = 5;
  var blockSize = 5;
  var sort = req.query.sort || 'latest';
  var orderSql = getPostOrderSql(sort);
  var whereSql = 'WHERE NVL(OK, 1) = 1';
  var binds = {};

  if (choice === 'TITLE_CONTENT') {
    whereSql += ' AND (TITLE LIKE :search OR CONTENT LIKE :search)';
    binds.search = search;
  } else if (choice === 'WRITER' || choice === 'CONTENT' || choice === 'TITLE') {
    whereSql += ' AND ' + choice + ' LIKE :search';
    binds.search = search;
  }

  var countSql = 'SELECT COUNT(*) FROM BBS ' + whereSql;
  runQuery(countSql, binds, function(countErr, countResult) {
    if (countErr) {
      console.error('요청 처리 중 오류가 발생했습니다.');
      res.render('bbs/list', emptyListData(currentPage, pageSize, blockSize, req, sort));
      return;
    }

    var totalRecords = parseInt(countResult.rows[0][0], 10);
    var totalPage = Math.ceil(totalRecords / pageSize);
    var stNum = (currentPage - 1) * pageSize;
    var sql = getPostListSelectSql(whereSql, orderSql);
    var queryBinds = Object.assign({}, binds, { offset: stNum, pageSize: pageSize });

    runQuery(sql, queryBinds, function(err, rows) {
      if (err) console.error('요청 처리 중 오류가 발생했습니다.');
      res.render('bbs/list', {
        data: rows || { rows: [] },
        currentPage: currentPage,
        totalRecords: totalRecords,
        pageSize: pageSize,
        totalPage: totalPage,
        blockSize: blockSize,
        firstPage: 1,
        lastPage: totalPage,
        stNum: stNum,
        userId: req.session.user ? req.session.user.id : null,
        searchChoice: choice,
        searchKeyword: keyword,
        sort: sort
      });
    });
  });
});

module.exports = router;
