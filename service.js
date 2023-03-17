const http = require('http');
const shell = require('shelljs');
const eURL = require('url');
const site_server = http.createServer();
const logger = require('logger').createLogger("vpn.log");
const httpPort = 2022;


startHttpServer();
async function startHttpServer() {

    logger.info("http server start ...");

    site_server.on('error', (err)=>{
        logger.error("http server error ", err.stack);
    });

    site_server.on('request', async function (req, res) {

        logger.info("*** start request", req.method);

        try {

            let U = eURL.parse(req.url, true);
            logger.info("request info", req.method, JSON.stringify(U));

            if (req.method === "GET") {
                switch (U.pathname.replace(/^\/|\/$/g, '')) {
                    case "pull" :
                        await pull(req, res, U.query);
                        break;
                    default :
                        logger.info("pathname not found !", U.pathname);
                }
            }

            logger.info("*** end request");

        }catch (e) {
            logger.error("DANGER !!!! >>> in request ", e.message);
        }

        res.end();
    });

    site_server.listen(httpPort);
    logger.info("http server listen on " + httpPort);
}

async function pull(req, res, query){

    shell.exec("git reset --hard HEAD");
    shell.exec("git pull");

    setTimeout(()=>{

        shell.exec("npm install");

        setTimeout(()=>{

            site_server.close().once('close', () => {
                console.log('Server stopped')
                shell.exec("supervisorctl restart OvpnManager");
            });


        }, 10000)

    }, 10000);

}