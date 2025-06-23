// const { createProxyMiddleware } = require('http-proxy-middleware');

// class Routes {
//   constructor(middleware) {
//     this.middleware = middleware;
//     this.testingMode = true;
//     this.setupUrls();
//   }

//   setupUrls() {
//     this.urls = {
//       UPMS_URL: this.testingMode ? 'http://localhost:5001' : 'https://isa-database-microservice.onrender.com',
//       AUTH_URL: this.testingMode ? 'http://localhost:5000' : 'https://auth-microservice-of4o.onrender.com',
//       FRONTEND_URL: this.testingMode ? 'http://localhost:8080' : 'https://isa-facade.azurewebsites.net',
//       AI_URL: this.testingMode ? 'http://localhost:8081' : 'https://ai-microservice-x34z.onrender.com',
//       DOCS_URL: this.testingMode ? 'http://localhost:8082' : 'https://swagger-docs.azurewebsites.net',
//     };
//   }

//   configureRoutes(app) {
//     this.setupStaticRoutes(app);
//     this.setupProxyRoutes(app);
//   }

//   setupStaticRoutes(app) {
//     app.use('/static', createProxyMiddleware({
//       target: this.urls.FRONTEND_URL,
//       changeOrigin: true,
//       pathRewrite: { '^/static': '/static' },
//     }));
//   }

//   setupProxyRoutes(app) {
//     // Define route configurations
//     const routes = [
//       { method: 'get', path: '/login', target: 'FRONTEND_URL' },
//       { method: 'post', path: '/login', target: 'AUTH_URL' },
//       { method: 'post', path: '/register', target: 'AUTH_URL' },
//       { method: 'post', path: '/forgot-password', target: 'AUTH_URL' },
//       { method: 'get', path: '/protected', target: 'AUTH_URL' },
//       { method: 'get', path: '/dashboard', target: 'FRONTEND_URL' },
//       { method: 'get', path: '/reset', target: 'FRONTEND_URL' },
//       { method: 'get', path: '/forgot', target: 'FRONTEND_URL' },
//       { method: 'get', path: '/', target: 'FRONTEND_URL' },
//       { method: 'get', path: '/register', target: 'FRONTEND_URL' },
//       { method: 'get', path: '/message', target: 'FRONTEND_URL' },
//       { method: 'post', path: '/reset-password', target: 'UPMS_URL' },
//       { method: 'get', path: '/favicon.ico', target: 'FRONTEND_URL' },
//       { method: 'post', path: '/detect', target: 'AI_URL' },
//       { method: 'get', path: '/detect', target: 'FRONTEND_URL' },
//       { method: 'get', path: '/admin', target: 'FRONTEND_URL' },
//       { method: 'post', path: '/query', target: 'UPMS_URL' },
//       { method: 'get', path: '/docs', target: 'DOCS_URL' },
//       { method: 'get', path: '/docs/*', target: 'DOCS_URL' },
//       { method: 'get', path: '/api-docs', target: 'DOCS_URL' },
//     ];

//     // Setup routes
//     routes.forEach((route) => {
//       app[route.method](route.path, createProxyMiddleware({
//         target: this.urls[route.target],
//         changeOrigin: true,
//         logLevel: 'debug', // Enable detailed logging
//         onProxyReq: (proxyReq, req, res) => {
//           console.log(`[Proxy Request] ${req.method} ${req.originalUrl} -> ${this.urls[route.target]}${req.path}`);
//         },
//         onProxyRes: (proxyRes, req, res) => {
//           console.log(`[Proxy Response] ${req.method} ${req.originalUrl} -> ${proxyRes.statusCode}`);
//         },
//         onError: (err, req, res) => {
//           console.error(`[Proxy Error] ${req.method} ${req.originalUrl}:`, err);
//           res.status(500).send('Proxy encountered an error.');
//         },
//       }));
//     });
//   }
// }

// module.exports = Routes;