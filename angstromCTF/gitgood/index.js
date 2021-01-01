const express = require("express");
const morgan = require("morgan");
const app = express();

const port = process.env.PORT || 9090;

app.use(morgan("tiny"));
app.use(express.static("."));

app.listen(port, function() {
    console.log(`App listening on port ${port}!`);
})