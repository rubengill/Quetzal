require('dotenv').config({ path: '../.env' });
const Server = require('./modules/server');

const server = new Server(process.env.PORT_FRONTEND || 8080);
server.start();