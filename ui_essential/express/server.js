const express = require('express');
const path = require('path');
const cors = require('cors');
const bodyParser = require('body-parser');
const app = express();
const server = require('http').Server(app);
const io = require('socket.io')(server);

app.use(cors());
app.use(bodyParser.json({ limit: '1024mb' }));
app.use(bodyParser.urlencoded({ limit: '1024mb', extended: true }));
app.use(express.static(path.join(__dirname,'..','dist')));
let websocketClients = Array();
app.post('/api/post', (req, res) => {
  console.log('received post');
  websocketClients.forEach(client => {
    client.emit('post', req.body);
  });
  res.send('received');
});
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname,'..','dist','index.html'));
});

server.listen(process.env.PORT || 8080);

io.on('connection', function(socket){
  websocketClients.push(socket);
  socket.emit('connected', 'Connected to the USC ISI Hackathon');
  socket.on('message', function(data){
    io.emit('message', data);
    socket.emit('confirmation', data);
  });
});