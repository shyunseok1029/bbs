var express = require('express');
var router = express.Router();
var oracledb = require('oracledb');
var crypto = require('crypto');
const session = require('express-session');

oracledb.autoCommit = true;

var dbconfig = require('../config').db;

router.get('/', function(req, res, next) {
  res.redirect('/bbs/list');
});

router.get('/login', function(req, res, next) {
  var code = 0;
  if(req.session.user)  code = 3;
  res.render('bbs/login', {errcode : code});
});

router.get('/logout', function(req, res, next) {
  
  if(req.session.user)  req.session.destroy();

  res.redirect('/bbs/list');  
});

router.get('/signup', function(req, res, next) {
  var code = 0;
  if( req.session.user )  code = 1;
  res.render('bbs/signup', {code : code});  
});

router.post('/signupsave', function(req, res, next) {
  var id = req.body.id, pw1 = req.body.pw1, pw2 = req.body.pw2;
  var name = req.body.name;
  var email = req.body.email;
  var code = 0 ; // 1-두개의 패스워드 틀린경우 
  
  if( pw1 != pw2)
  {
      code = 1;
      res.render('bbs/error', {errcode : code});
      return;
  }
  if( id == "" || pw1 == "" || name == "")
  {
      code = 2;
      res.render('bbs/error', {errcode : code});
      return;
  }

  var salt = Math.round(new Date().valueOf()*Math.random()) + "";
  var hashPassword = crypto.createHash("sha512").update(pw1+salt).digest("base64");


  var sql = "INSERT INTO LOGIN(ID,PASSWORD,NAME,EMAIL,SALT) VALUES( '" +id+ "','"+hashPassword+"','"+name+"','"+email+"','"+salt+"')";

  oracledb.getConnection(dbconfig, function(err,connection){
      
    connection.execute(sql, function(err, result){
      if(err)
      {
          code = 3;
          res.render('bbs/error', {errcode : code});
          return;
      } 

      res.redirect('/bbs/login');
    });  
  });
});


router.get('/updatesignup',function(req,res,next) {
  var code = 0;

  if(req.session.user) 
  {
    oracledb.getConnection(dbconfig,function(err,connection){
      var sql = "SELECT ID, PASSWORD, NAME, EMAIL FROM LOGIN WHERE ID = '"+req.session.user.id+"'";

      connection.execute(sql,function(err,rows){
          if(err) console.error('요청 처리 중 오류가 발생했습니다.');

          res.render('bbs/updatesignform', rows);
          connection.release();
     });
    });
  }
  else
  {
    code = 4;
    res.render('bbs/error', {errcode : code});
    return;
  }
});

router.post('/updatesignsave',function(req,res,next){
  var id= req.body.id, pw = req.body.pw1, name=req.body.name, email=req.body.email;

  oracledb.getConnection(dbconfig,function(err,connection){
      
      var sql="UPDATE LOGIN"+
              " SET ID= '" + id + "', PASSWORD='" + pw +"', NAME='" + name +"'" +
              ", EMAIL='" + email +"' " + "WHERE ID='" + id + "'";

      connection.execute(sql,function(err,rows){
          if(err) console.error('요청 처리 중 오류가 발생했습니다.');

          res.redirect('/bbs/list');
          connection.release();
      });
  });
});

router.post('/logincheck', function(req, res, next) {
  var id = req.body.id;
  var pw = req.body.password;
  var code =0;
  oracledb.getConnection(dbconfig, function(err,connection){
    var sql = "SELECT OK, PASSWORD, SALT FROM LOGIN WHERE ID = '"+id+"'";
  
    connection.execute(sql, function(err, result){
      if( err) console.error('요청 처리 중 오류가 발생했습니다.');
      
      var dbHashPassword = result.rows[0][1];
      var dbSalt = result.rows[0][2];

      var hashPassword = crypto.createHash("sha512").update(pw+dbSalt).digest("base64");

      if( result.rows.length < 1)
      {

        code = 1;
        res.render('bbs/login',{errcode : code});
        return;
      }
      else if( hashPassword == dbHashPassword )
      {
        const paramID = req.body.id || req.query.id;
        const pwd = req.body.password || req.query.password;

        if( req.session.user )
        {

        }
        else
        {

          req.session.user = {
            id : paramID,
            pw : pwd,
            authorized : true,
          };
        }
      }
      else
      {

        code = 2;
        res.render('bbs/login',{errcode : code});
        return;
      }
      res.redirect('/bbs/list');
      connection.release();
    });
  });
});

async function countRecord(){
  return new Promise(function(resolve,reject) {
      
      oracledb.getConnection(dbconfig,function(err,connection) {

          var sql = "SELECT COUNT(*) FROM BBS ";
          
          connection.execute(sql,function(err,count){
              if(err) console.error('요청 처리 중 오류가 발생했습니다.');
              var totalRecords=parseInt(count.rows);

              connection.release();
              resolve(totalRecords);
          });
      });
  });
}

router.get('/list',async function(req,res,next) {
  var stNum=0, totalRecords=0, totalPage=0, firstPage=0, lastPage=0, currentPage=1, blockSize=5, pageSize=5;

  countRecord().then(function(totalRecords) {
      if(req.query.currentPage!=undefined) currentPage=parseInt(req.query.currentPage);

      totalPage=Math.ceil(totalRecords/pageSize);

      firstPage=1;
      lastPage=totalPage;
      stNum=(currentPage-1)*pageSize;

      oracledb.getConnection(dbconfig,function(err,connection){
      
          var sql = "SELECT NO, TITLE, WRITER, CONTENT, to_char(REGDATE,'yyyy-mm-dd hh24:mi:ss'), OK, COUNT" + 
                     " FROM BBS ORDER BY NO DESC OFFSET "+stNum+" ROWS FETCH NEXT "+pageSize+" ROWS ONLY";
      
          connection.execute(sql,function(err,rows){
              if(err) console.error('요청 처리 중 오류가 발생했습니다.');

              res.render('bbs/list', {data:rows,currentPage:currentPage,totalRecords:totalRecords,pageSize:pageSize,
                                      totalPage:totalPage,blockSize:blockSize,firstPage:firstPage,lastPage:lastPage,
                                     stNum:stNum});
              connection.release();
          });
      });
  })         
});

router.get('/form',function(req,res,next){
  if(req.session.user)
       res.render('bbs/form', {id: req.session.user.id});
  else
    res.render('bbs/form', {id:0});
});

router.post('/save',function(req,res,next){
  oracledb.getConnection(dbconfig,function(err,connection){
      var sql = "";
 
      sql = "INSERT INTO BBS(NO, TITLE, CONTENT, WRITER, REGDATE) VALUES(bbs_seq.nextval,'"
          + req.body.brdtitle + "','" + req.body.brdmemo + "','" + req.body.brdwriter+"', sysdate)";

      connection.execute(sql,function(err,rows){

        if(err) console.error('요청 처리 중 오류가 발생했습니다.');
        if(rows) res.redirect('/bbs/list');

          connection.release();
      });
  });
});

router.get('/read_count',function(req,res,next){
  oracledb.getConnection(dbconfig,function(err,connection){

      var sql = "UPDATE BBS SET COUNT = COUNT +'"+ 1 +"' WHERE NO="+req.query.brdno;

      connection.execute(sql,function(err,rows){
          if(err) console.error('요청 처리 중 오류가 발생했습니다.');

          res.redirect('/bbs/read?brdno='+req.query.brdno);
          connection.release();
      });
  });
});

async function read_bbs(brdno){
  return new Promise(function(resolve,reject) {
      
      oracledb.getConnection(dbconfig,function(err,connection) {

          var sql = "SELECT NO, TITLE, WRITER, CONTENT, to_char(REGDATE,'yyyy-mm-dd'), OK, COUNT  FROM BBS "+
                    " WHERE NO ="+brdno;
          
          connection.execute(sql,function(err,retBBS){
              if(err) console.error('요청 처리 중 오류가 발생했습니다.');
                       
              connection.release();
              resolve(retBBS);
          });
      });
  });
}


router.get('/read',function(req,res,next){

  read_bbs(req.query.brdno).then( function(retBBS) {
    oracledb.getConnection(dbconfig,function(err,connection){
     
      var sql = "SELECT NO, BBS_NO, WRITER, CONTENT,  to_char(REGDATE,'yyyy-mm-dd'), WCOUNT, OK" +
              " FROM BBSW" +
              " WHERE BBS_NO="+req.query.brdno +
              " ORDER BY NO DESC";

      connection.execute(sql,function(err,rows){
          if(err) console.error('요청 처리 중 오류가 발생했습니다.');
          
          res.render('bbs/read', {bbs:retBBS, wbbs:rows});
          connection.release();
      });
    });
  });
});

router.post('/wsave',function(req,res,next){
  var bbsno = req.body.bbsno;
  var code=0;
  if( req.session.user )
  {
    var sql="INSERT INTO BBSW(NO, BBS_NO, WRITER, CONTENT, REGDATE) VALUES(bbsw_seq.nextval,"
          + bbsno+",'"+req.session.user.id+"','"+req.body.wbrdmemo+"', sysdate)";

    oracledb.getConnection(dbconfig,function(err,connection) {
        connection.execute(sql,function(err,rows){
          if(err) console.error('요청 처리 중 오류가 발생했습니다.');
          res.redirect("/bbs/read?brdno="+bbsno);
          connection.release();
        });
    });
  }
  else
  {
    code = 5;
    res.render('bbs/error', {errcode : code});
    return;
  }
});


router.get('/update',function(req,res,next) {
    oracledb.getConnection(dbconfig,function(err,connection){
        var sql = "SELECT NO, TITLE, CONTENT, WRITER, to_char(REGDATE,'yyyy-mm-dd') FROM BBS WHERE NO="+req.query.brdno;
  
        connection.execute(sql,function(err,rows){
            if(err) console.error('요청 처리 중 오류가 발생했습니다.');
  
            res.render('bbs/updateform',rows);
            connection.release();
       });
    });
  });

router.get('/delete', function(req,res,next){
    oracledb.getConnection(dbconfig,function(err,connection){
      var sql = "UPDATE BBS SET OK=0" +
                " WHERE NO=" + req.query.brdno;

      connection.execute(sql,function(err,rows){
        if(err) console.error('요청 처리 중 오류가 발생했습니다.');
  
        res.redirect('/bbs/list');
        connection.release();
      });
    });
});
    

router.post('/updatesave',function(req,res,next){
  oracledb.getConnection(dbconfig,function(err,connection){
      var sql = "";
      if(req.body.brdno){
          sql="UPDATE BBS"+
              " SET TITLE= '" + req.body.brdtitle + "', CONTENT='" + req.body.brdmemo+"', WRITER='" + req.body.brdwriter+"' " 
              + "WHERE NO=" + req.body.brdno;
      }

      connection.execute(sql,function(err,rows){
          if(err) console.error('요청 처리 중 오류가 발생했습니다.');

          res.redirect('/bbs/list');
          connection.release();
      });
  });
});

router.get('/search',function(req,res,next){

  oracledb.getConnection(dbconfig,function(err,connection){
      var sql;
      if(req.query.choice=="TITLE_CONTENT"){
          sql = "SELECT NO, TITLE, WRITER, CONTENT, to_char(REGDATE,'yyyy-mm-dd hh24:mi:ss'), OK" + 
          " FROM BBS WHERE TITLE LIKE '%" + req.query.search + "%' OR CONTENT LIKE '%"+  req.query.search +
          "%' ORDER BY NO DESC";
      }
      else{
          sql = "SELECT NO, TITLE, WRITER, CONTENT, to_char(REGDATE,'yyyy-mm-dd hh24:mi:ss'), OK" + 
      " FROM BBS WHERE " +req.query.choice +" LIKE '%" + req.query.search + "%'  ORDER BY NO DESC";
      }
      connection.execute(sql,function(err,rows){
          if(err) console.error('요청 처리 중 오류가 발생했습니다.');

          res.render('bbs/list',rows);
          connection.release();
      });
  });
});

module.exports = router;
