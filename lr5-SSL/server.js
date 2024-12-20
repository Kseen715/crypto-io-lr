const fs = require('fs');
const https = require('https');
 
https
  .createServer(
    {
      requestCert: false,
      rejectUnauthorized: false,
      ca: fs.readFileSync('root_ca.crt'),
      cert: fs.readFileSync('server.crt'),
      key: fs.readFileSync('server.key')
    },
    (req, res) => {
      console.log("req.client.authorized: ", req.client.authorized)
      if (req.client.authorized) {
        const cert = req.socket.getPeerCertificate(false) // true - получить все сертификаты, false - последний
        console.log("cert: ", cert)
    }
      res.end('Hello, world!');
    }
  )
  .listen(9443);