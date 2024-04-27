const {exec}=require('child_process');
const express = require("express");
const app = express();
const fs=require('fs/promises');
const path = require("path");
app.set("views", path.join(__dirname, "views"));

var state=false;

app.set("view engine", "ejs");

app.get('/',async function(request,response){
    const content=await fs.readFile('./myfile.txt', 'utf-8');
    // console.log(content);
    response.render("index",{
        content:content,
    });
});

app.get("/myfile.txt", async function(request,response){
    const options = {
        root: path.join(__dirname)
    };
    const fileName = 'myfile.txt';
    response.sendFile('myfile.txt',options,function (err) {
        if (err) {
            console.error('Error sending file:', err);
        } else {
            console.log('Sent:', fileName);
        }
    });
});

module.exports=app;