const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

const rooms = {};

app.get("/", (req, res) => {
  res.send("Chat server chal raha hai");
});

io.on("connection", (socket) => {
  socket.on("create_room", ({ room, name }) => {
    if (rooms[room]) return socket.emit("error_msg", "Room pehle se hai");
    rooms[room] = { leader: socket.id, members: { [socket.id]: name } };
    socket.join(room);
    socket.emit("joined", { room, leader: true });
  });

  socket.on("join_room", ({ room, name }) => {
    if (!rooms[room]) return socket.emit("error_msg", "Room nahi mila");
    rooms[room].members[socket.id] = name;
    socket.join(room);
    socket.emit("joined", { room, leader: false });
    io.to(room).emit("system", name + " juda");
  });

  socket.on("message", ({ room, text }) => {
    const r = rooms[room];
    if (!r || !r.members[socket.id]) return;
    io.to(room).emit("message", { name: r.members[socket.id], text });
  });

  socket.on("kick", ({ room, targetId }) => {
    const r = rooms[room];
    if (!r || r.leader !== socket.id) return;
    io.to(targetId).emit("kicked");
    io.sockets.sockets.get(targetId)?.leave(room);
    delete r.members[targetId];
    io.to(room).emit("system", "Ek member ko nikala gaya");
  });

  socket.on("disconnect", () => {
    for (const room in rooms) {
      const r = rooms[room];
      if (!r.members[socket.id]) continue;
      delete r.members[socket.id];
      if (r.leader === socket.id) {
        const ids = Object.keys(r.members);
        if (ids.length) r.leader = ids[0];
        else delete rooms[room];
      }
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log("Server on " + PORT));
