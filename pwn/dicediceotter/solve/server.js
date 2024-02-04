var express = require('express');
var { spawnSync } = require('child_process');
var app = express();

const PORT = process.env.PORT || 1337;

app.use((req, res, next) => {
  console.log(decodeURIComponent(req.originalUrl));
  next();
})

app.use(express.static(__dirname + "/public"));

app.listen(PORT, '0.0.0.0', () => {
  console.log("listening ", PORT)
});
