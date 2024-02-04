var express = require('express');
var app = express();

const PORT = process.env.PORT || 1337;

app.use(express.static(__dirname + "/public"));

app.listen(PORT, '0.0.0.0', () => {
  console.log("listening ", PORT)
});
