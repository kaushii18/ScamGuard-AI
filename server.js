console.log("ScamGuard AI is starting...");

const express = require("express");
const app = express();

app.use(express.static("public"));

app.listen(3000, () => {
    console.log("ScamGuard AI server is running...");
});