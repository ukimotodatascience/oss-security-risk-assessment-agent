// host: '0.0.0.0' - This is a comment and should be ignored (False positive check)

const express = require('express');
const app = express();

app.get('/', (req, res) => {
  res.send('Hello World!');
});

/*
  Block comment check
  listen('0.0.0.0');
*/

// Active code that should be caught
app.listen(8080, '0.0.0.0', () => {
  console.log('App is running');
});

// String literal that isn't a binding should ideally be ignored, but checking the behavior
const test = "0.0.0.0";
