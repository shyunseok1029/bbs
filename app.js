var config = require('./config');
var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var expressSession = require('express-session');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
var bbsRouter = require('./routes/bbs');
var upload = require('./lib/upload');
var csrf = require('./lib/csrf');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(
  expressSession(
    {
      secret: config.sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 2 },
    }
  )
)

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
// Parse multipart into bounded memory only after authentication; no files are written here.
app.use('/bbs', function(req, res, next) {
  if (req.method !== 'POST' || !['/save', '/updatesave'].includes(req.path) || !req.is('multipart/form-data')) return next();
  if (!req.session.user) return res.status(401).send('로그인이 필요합니다.');
  upload.parse(req, res, function(err) { if (err) return res.status(400).send('첨부파일 요청이 올바르지 않습니다.'); next(); });
});
app.use(csrf);
app.use('/uploads', function(req, res) { res.sendStatus(404); });
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', indexRouter);
app.use('/users', usersRouter);
app.use('/bbs',bbsRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('bbs/error');
});

module.exports = app;
