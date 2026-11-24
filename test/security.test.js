'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const request = require('supertest');
const passwords = require('../lib/password');
const upload = require('../lib/upload');
process.env.DB_USER = 'test'; process.env.DB_PASSWORD = 'test';
process.env.DB_CONNECT_STRING = 'unused'; process.env.SESSION_SECRET = 'test-secret';
const oracle = require('oracledb');
const testHash = passwords.hash('example-password');
let calls = [];
let queryHandler = null;
oracle.getConnection = function(config, cb) {
  cb(null, {execute(sql, binds, done) {
    calls.push({sql, binds});
    if (queryHandler) { const result = queryHandler(sql, binds); if (result) return done(null, result); }
    if (sql.startsWith('SELECT OK, PASSWORD')) return done(null, {rows: [[1, testHash, null]]});
    if (sql.startsWith('SELECT WRITER FROM BBS')) return done(null, {rows: [['owner']]});
    done(null, {rows: [], rowsAffected: 0});
  }, release() {}});
};
const app = require('../app');
function token(html) { const m = html.match(/name="_csrf" value="([a-f0-9]{64})"/); assert.ok(m, 'CSRF token in form'); return m[1]; }
async function login(agent, id = 'other') {
  let r = await agent.get('/bbs/login');
  r = await agent.post('/bbs/logincheck').type('form').send({_csrf: token(r.text), id, password: 'example-password'});
  assert.equal(r.status, 302);
  r = await agent.get('/bbs/form'); assert.equal(r.status, 200);
  return token(r.text);
}
test('passwords use random scrypt salts; verify legacy hashes without modifying data', () => {
  const a = passwords.hash('pw'), b = passwords.hash('pw');
  assert.notEqual(a, b); assert.ok(passwords.verify('pw', a)); assert.equal(passwords.verify('wrong', a), false);
  const old = require('node:crypto').createHash('sha512').update('pw' + 'salt').digest('base64');
  assert.ok(passwords.verify('pw', old, 'salt')); assert.equal(passwords.verify('pw', 'scrypt$invalid'), false);
});
test('missing env reports names without values', () => {
  const r = spawnSync(process.execPath, ['-e', "require('./config')"], {cwd: process.cwd(), env: {PATH: process.env.PATH}, encoding:'utf8'});
  assert.notEqual(r.status, 0); assert.match(r.stderr, /DB_USER/); assert.match(r.stderr, /SESSION_SECRET/);
});
test('CSRF rejects missing tokens, old GET mutation methods are rejected', async () => {
  const agent = request.agent(app); await agent.get('/bbs/login');
  assert.equal((await agent.post('/bbs/logincheck').type('form').send({id:'x'})).status, 403);
  for (const url of ['/bbs/delete?brdno=1','/bbs/good?brdno=1','/bbs/logout','/bbs/read_count?brdno=1']) assert.equal((await agent.get(url)).status, 404);
  assert.equal((await agent.get('/bbs/findpw')).status, 503);
});
test('unauthenticated uploads are rejected before query and file processing', async () => {
  calls = [];
  const r = await request(app).post('/bbs/save').field('_csrf', 'bad').attach('userfile', Buffer.from('hi'), 'x.txt');
  assert.equal(r.status, 401); assert.equal(calls.length, 0);
});
test('other users cannot modify posts; comments bind current writer', async () => {
  const agent = request.agent(app), csrf = await login(agent);
  calls = [];
  assert.equal((await agent.post('/bbs/delete?brdno=7').type('form').send({_csrf:csrf})).status, 403);
  assert.equal(calls.filter(c=>/^UPDATE BBS SET OK/.test(c.sql)).length, 0);
  calls = [];
  assert.equal((await agent.post('/bbs/updatesave').field('_csrf',csrf).field('brdno','7').field('brdtitle','title').field('brdmemo','body').attach('userfile', Buffer.from('hi'), 'x.txt')).status, 403);
  assert.equal(calls.filter(c=>/^UPDATE BBS SET TITLE/.test(c.sql)).length, 0);
  calls = [];
  await agent.post('/bbs/w_update').type('form').send({_csrf:csrf,wno:'11',bbsno:'7',wbrdmemo:'changed'});
  const update = calls.find(c=>c.sql.startsWith('UPDATE BBSW SET CONTENT'));
  assert.ok(update); assert.match(update.sql, /WRITER = :writer/); assert.equal(update.binds.writer,'other');
});
test('uploads reject invalid type, oversize and missing CSRF', async () => {
  const agent = request.agent(app), csrf = await login(agent);
  const send = (buffer,name,include=true) => { let r=agent.post('/bbs/save').field('brdtitle','t').field('brdmemo','c'); if(include)r=r.field('_csrf',csrf); return r.attach('userfile',buffer,name); };
  assert.equal((await send(Buffer.from('hello'),'file.exe')).status,400);
  assert.equal((await send(Buffer.from('not an image'),'file.png')).status,400);
  assert.equal((await send(Buffer.from('hello'),'file.txt',false)).status,403);
  assert.equal((await send(Buffer.alloc(upload.maxSize+1,65),'file.txt')).status,400);
  assert.ok(upload.validate({originalname:'x.txt',buffer:Buffer.from('hello')}));
  assert.equal(upload.validate({originalname:'x.txt',buffer:Buffer.from([0])}),false);
});

test('session renewal invalidates the previous CSRF token', async () => {
  const agent = request.agent(app); const initial = await agent.get('/bbs/login');
  const old = token(initial.text);
  assert.equal((await agent.post('/bbs/logincheck').type('form').send({_csrf: old, id:'owner',password:'example-password'})).status, 302);
  assert.equal((await agent.post('/bbs/wsave').type('form').send({_csrf:old,bbsno:'1',wbrdmemo:'x'})).status, 403);
});
test('all EJS templates compile; every POST form has exactly one token', () => {
  const fs = require('node:fs'), ejs = require('ejs');
  for (const name of fs.readdirSync('views/bbs').filter(n => n.endsWith('.ejs'))) {
    const source = fs.readFileSync('views/bbs/' + name, 'utf8'); ejs.compile(source);
    const forms = source.matchAll(/<form\b(?:<%.*?%>|[^>])*\bmethod="post"(?:<%.*?%>|[^>])*>([\s\S]*?)<\/form>/gi);
    for (const form of forms) assert.equal((form[1].match(/name="_csrf"/g) || []).length, 1, name);
  }
});


test('signup stores scrypt hash and never stores the submitted password', async t => {
  queryHandler = (sql) => sql.startsWith('SELECT COUNT(*) FROM LOGIN') ? {rows:[[0]]} : null;
  t.after(() => { queryHandler = null; });
  const agent = request.agent(app), page = await agent.get('/bbs/signup'); calls = [];
  const response = await agent.post('/bbs/signupsave').type('form').send({_csrf:token(page.text),id:'sampleid',pw1:'sample-password',pw2:'sample-password',name:'Sample',email:'sample@example.invalid'});
  assert.equal(response.status,302);
  const insert = calls.find(c=>c.sql.startsWith('INSERT INTO LOGIN'));
  assert.ok(insert); assert.match(insert.binds.password, /^scrypt\$/); assert.ok(passwords.verify('sample-password',insert.binds.password));
});

test('login rejects incorrect password and unauthenticated comment writes', async () => {
  const agent = request.agent(app), page = await agent.get('/bbs/login');
  let response = await agent.post('/bbs/logincheck').type('form').send({_csrf:token(page.text),id:'other',password:'incorrect'});
  assert.equal(response.status,200); assert.match(response.text,/패스워드가 틀립니다/);
  calls = [];
  response = await agent.post('/bbs/wsave').type('form').send({_csrf:token(response.text),bbsno:'1',wbrdmemo:'message'});
  assert.equal(response.status,401); assert.equal(calls.length,0);
});

test('reaction POST requires CSRF and inserts a user-bound reaction', async t => {
  const agent = request.agent(app), csrf = await login(agent);
  queryHandler = sql => sql.startsWith('SELECT REACTION FROM BBS_REACTION') ? {rows:[]} : null;
  t.after(() => {queryHandler = null;}); calls = [];
  assert.equal((await agent.post('/bbs/good?brdno=3').type('form').send({})).status,403); assert.equal(calls.length,0);
  assert.equal((await agent.post('/bbs/good?brdno=3').type('form').send({_csrf:csrf})).status,302);
  const insert = calls.find(c=>c.sql.startsWith('INSERT INTO BBS_REACTION'));
  assert.ok(insert); assert.equal(insert.binds.userId,'other'); assert.equal(insert.binds.reaction,'GOOD');
});

test('search uses binds and pagination on the Oracle query', async t => {
  queryHandler = sql => sql.startsWith('SELECT COUNT(*) FROM BBS') ? {rows:[[12]]} : {rows:[]};
  t.after(() => {queryHandler = null;}); calls = [];
  const response = await request(app).get('/bbs/search?choice=TITLE&search=term&currentPage=2&sort=likes');
  assert.equal(response.status,200); assert.match(response.text,/검색/);
  const q = calls.find(c=>c.sql.includes('OFFSET :offset'));
  assert.ok(q); assert.equal(q.binds.search,'%term%'); assert.equal(q.binds.offset,5); assert.equal(q.binds.pageSize,5);
});

test('attachment download uses visible post lookup and safe response headers', async t => {
  const fs=require('node:fs'), path=require('node:path'), os=require('node:os');
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'bbs-download-test-')), old=upload.directory;
  upload.directory=dir; const name='a'.repeat(48)+'.txt'; fs.writeFileSync(path.join(dir,name),'sample');
  queryHandler=sql=>sql.startsWith('SELECT FILENAME, ORIGINAL_FILENAME') ? {rows:[[name,'example.txt']]} : null;
  t.after(()=>{queryHandler=null;upload.directory=old;fs.rmSync(dir,{recursive:true,force:true});});
  const response=await request(app).get('/bbs/attachment/1');
  assert.equal(response.status,200); assert.match(response.headers['content-disposition'],/^attachment/);
  assert.equal(response.headers['x-content-type-options'],'nosniff');
  assert.ok(calls.some(c=>c.sql.includes('NVL(OK, 1) = 1')));
});

test('deleted post lookup excludes disabled rows and preserves bound ID', async t => {
  queryHandler=sql=>sql.includes('FROM BBS WHERE NO = :brdno') ? {rows:[]} : null;
  t.after(()=>{queryHandler=null;}); calls=[];
  assert.equal((await request(app).get('/bbs/read?brdno=42')).status,302);
  const q=calls.find(c=>c.sql.includes('FROM BBS WHERE NO = :brdno'));
  assert.ok(q); assert.match(q.sql,/NVL\(OK, 1\) = 1/); assert.equal(q.binds.brdno,'42');
});

test('password change requires the current password', async t => {
  const agent=request.agent(app), csrf=await login(agent);
  queryHandler=sql=>sql.startsWith('SELECT PASSWORD, SALT') ? {rows:[[testHash,null]]} : {rows:[],rowsAffected:1};
  t.after(()=>{queryHandler=null;}); calls=[];
  const body={_csrf:csrf,pw1:'new-password',pw2:'new-password',currentPassword:'wrong',name:'Sample',email:'sample@example.invalid'};
  assert.equal((await agent.post('/bbs/updatesignsave').type('form').send(body)).status,403);
  assert.ok(!calls.some(c=>c.sql.startsWith('UPDATE LOGIN SET PASSWORD')));
  body.currentPassword='example-password';
  assert.equal((await agent.post('/bbs/updatesignsave').type('form').send(body)).status,302);
  const q=calls.find(c=>c.sql.startsWith('UPDATE LOGIN SET PASSWORD'));
  assert.ok(q); assert.ok(passwords.verify('new-password',q.binds.password));
});

test('comment deletion uses the logged-in author in the query', async () => {
  const agent=request.agent(app), csrf=await login(agent); calls=[];
  assert.equal((await agent.post('/bbs/w_delete?brdno=3&wno=7').type('form').send({_csrf:csrf})).status,302);
  const q=calls.find(c=>c.sql.startsWith('UPDATE BBSW SET OK'));
  assert.ok(q); assert.match(q.sql,/WRITER = :writer/); assert.equal(q.binds.writer,'other');
});

test('detail renders safe attachment link and upload guidance is present', async t => {
  queryHandler = sql => {
    if (sql.startsWith('SELECT NO, TITLE, WRITER, CONTENT')) return {rows:[[1,'Title','owner','Body','date',1,0,0,0,'a'.repeat(48)+'.txt','file.txt']]};
    if (sql.startsWith('SELECT NO, BBS_NO, WRITER')) return {rows:[]};
    return null;
  };
  t.after(()=>{queryHandler=null;});
  const detail=await request(app).get('/bbs/read?brdno=1');
  assert.equal(detail.status,200); assert.match(detail.text,/\/bbs\/attachment\/1/); assert.doesNotMatch(detail.text,/<img[^>]+\/uploads\//);
  const agent=request.agent(app); await login(agent);
  const form=await agent.get('/bbs/form'); assert.match(form.text,/TXT\(UTF-8\), PDF, PNG, JPG/);
  const loginPage=await request(app).get('/bbs/login'); assert.match(loginPage.text,/비밀번호 재설정 준비 중/);
});

test('file size boundary permits 10 MiB and rejects the next byte', async t => {
  const agent=request.agent(app), csrf=await login(agent), save=upload.save;
  upload.save=()=>({filename:'b'.repeat(48)+'.txt',originalname:'boundary.txt'});
  queryHandler=sql=>sql.startsWith('INSERT INTO BBS(') ? {rowsAffected:1} : null;
  t.after(()=>{upload.save=save;queryHandler=null;});
  const send=buffer=>agent.post('/bbs/save').field('_csrf',csrf).field('brdtitle','title').field('brdmemo','body').attach('userfile',buffer,'boundary.txt');
  assert.equal((await send(Buffer.alloc(upload.maxSize,65))).status,302);
  assert.equal((await send(Buffer.alloc(upload.maxSize+1,65))).status,400);
});

test('comment dislike uses session user and requires CSRF', async t => {
  const agent=request.agent(app), csrf=await login(agent);
  queryHandler=sql=>sql.startsWith('SELECT REACTION FROM BBSW_REACTION') ? {rows:[]} : null;
  t.after(()=>{queryHandler=null;}); calls=[];
  assert.equal((await agent.post('/bbs/wbad?brdno=3&wno=7').type('form').send({})).status,403);
  assert.equal((await agent.post('/bbs/wbad?brdno=3&wno=7').type('form').send({_csrf:csrf})).status,302);
  const q=calls.find(c=>c.sql.startsWith('INSERT INTO BBSW_REACTION'));
  assert.ok(q); assert.equal(q.binds.userId,'other'); assert.equal(q.binds.reaction,'BAD');
});

test('local stylesheet references resolve', () => {
  const fs=require('node:fs'), path=require('node:path');
  for(const name of fs.readdirSync('views/bbs').filter(n=>n.endsWith('.ejs'))) {
    const source=fs.readFileSync(path.join('views/bbs',name),'utf8');
    for(const m of source.matchAll(/(?:href|src)="(\/stylesheets\/[^"<>]+)"/g)) assert.ok(fs.existsSync(path.join('public',m[1])),name+': '+m[1]);
  }
});
