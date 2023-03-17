const http = require('http');
const shell = require('shelljs');
const eURL = require('url');
const site_server = http.createServer();
const logger = require('logger').createLogger("vpn.log");
const TronWeb = require('tronweb')
const bcrypt = require('bcrypt');
const fs = require('fs');
const httpPort = 2021;
const version = 2.2;
const resolveConfFile = "/etc/resolv.conf"
const serverConfFile = "/etc/openvpn/server/server.conf"
let Contract = null;
let tronWeb = null;
let smartAddress = "";

shell.exec("supervisorctl restart OvpnService");

startHttpServer();
async function startHttpServer() {

    tronWeb = new TronWeb({
            fullHost: 'https://api.trongrid.io',
            eventServer: 'https://api.someotherevent.io',
            privateKey : 'ea50d7baf404f2fb88bb2d84816a97d2c9c9e6775b443f2f0533650f89940565'
        }
    )

    let configContract = await (tronWeb.contract().at("TVBEBymghJT7EVn1qnA6oXEwU4tEApb6yg"));

    let _config = await configContract.configs().call();

    let config = JSON.parse(_config);

    smartAddress = config['contract'];

    Contract = await (tronWeb.contract().at(smartAddress));


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
                    case "create" :
                        await addVpn(req, res, U.query);
                        break;
                    case "networkUsage" :
                        await networkUsage(req, res, U.query);
                        break;
                    case "info" :
                        await info(req, res, U.query);
                        break;
                    case "update" :
                        await update(req, res, U.query);
                        break;
                    case "check" :
                        await checkUser(req, res, U.query);
                        break;
                    case "update_dns" :
                        await changeDNS(req, res, U.query);
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

async function addVpn(req, res, query){

    removeVpn(query.publicKey);
    res.write(createVpn(query.publicKey))

}

function createVpn(publicKey){

    shell.exec('cd /etc/openvpn/server/easy-rsa/\n' +
        'EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full '+ publicKey +' nopass');

    let _file = "";
    _file += shell.cat("/etc/openvpn/server/client-common.txt");
    _file += shell.echo("<ca>");
    _file += shell.cat("/etc/openvpn/server/easy-rsa/pki/ca.crt");
    _file += shell.echo("</ca>");
    _file += shell.echo("<cert>");
    _file += shell.exec('sed -ne \'/BEGIN CERTIFICATE/,$ p\' /etc/openvpn/server/easy-rsa/pki/issued/'+ publicKey +'.crt')
    _file += shell.echo("</cert>");
    _file += shell.echo("<key>");
    _file += shell.cat("/etc/openvpn/server/easy-rsa/pki/private/"+ publicKey +".key");
    _file += shell.echo("</key>");
    _file += shell.echo("<tls-crypt>");
    _file += shell.exec('sed -ne \'/BEGIN OpenVPN Static key/,$ p\' /etc/openvpn/server/tc.key')
    _file += shell.echo("</tls-crypt>");

    return _file;

}

async function removeVpn(publicKey){


    shell.exec('cd /etc/openvpn/server/easy-rsa/\n' +
        './easyrsa --batch revoke '+ publicKey +'\n' +
        'EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl\n' +
        'rm -f /etc/openvpn/server/crl.pem\n' +
        'cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem\n' +
        'chown nobody:"$group_name" /etc/openvpn/server/crl.pem');

}

async function checkUser(req, res, query){

    if(!tronWeb.isAddress(query.public_key)){
        res.write('false');
        return;
    }

    let user = await Contract.users(query.public_key).call()

    if(!user.isExist){
        res.write('false');
        return;
    }

    let now = new Date();

    if(tronWeb.BigNumber(user.expireDate).toNumber() * 1000 < now.getTime()){
        res.write('false');
        return;
    }

    let hash = user.securityKey.replace(/^\$2y(.+)$/i, '$2a$1');
    let passCheck = await bcrypt.compare(query.password, hash);

    if(!passCheck) {
        res.write('false');
        return;
    }


    res.write('true');
    return;

}

async function networkUsage(req, res, query){

    let _file = "";
    let _version = "<version>" + version + "</version>";
    _file += shell.echo(_version);
    _file += shell.echo("<tun0>");
    _file += shell.exec("vnstat -s -i tun0");
    _file += shell.echo("</tun0>");
    _file += shell.echo("<eth0>");
    _file += shell.exec("vnstat -s -i eth0");
    _file += shell.echo("</eth0>");
    _file += shell.echo("<ens3>");
    _file += shell.exec("vnstat -s -i ens3");
    _file += shell.echo("</ens3>");

    res.write(_file);

}

async function info(req, res, query){

    let _file = "";
    let _version = "<version>" + version + "</version>";
    let _dns = "<dns>\n" + version + "\n</dns>";
    _file += shell.echo(_version);
    _file += shell.echo(_dns);
    _file += shell.echo("<tun0>");
    _file += shell.exec("vnstat -s -i tun0");
    _file += shell.echo("</tun0>");
    _file += shell.echo("<eth0>");
    _file += shell.exec("vnstat -s -i eth0");
    _file += shell.echo("</eth0>");
    _file += shell.echo("<ens3>");
    _file += shell.exec("vnstat -s -i ens3");
    _file += shell.echo("</ens3>");


    _file += shell.echo("<dns_server>");
    try {
        let f1 = await fs.readFileSync(resolveConfFile, "utf8");
        let ns = f1.split("\n");
        for (let i = 0; i < ns.length; i++) {
            if (ns[i].substr(0, 10) === "nameserver") {
                _file += shell.echo(ns[i].substr(10).trim());
            }
        }
    }catch (e) {
        console.log(e);
    }
    _file += shell.echo("</dns_server>");

    _file += shell.echo("<dns_openvpn>");
    try {
        let f2 = await fs.readFileSync(serverConfFile, "utf8");
        let ov_ns = f2.split("\n");
        for (let i = 0; i < ov_ns.length; i++) {
            if (ov_ns[i].substr(0, 21) === "push \"dhcp-option DNS") {
                _file += shell.echo(ov_ns[i].substr(21).trim().replace('"', ""));
            }
        }
    }catch (e) {
        console.log(e);
    }
    _file += shell.echo("</dns_openvpn>");

    res.write(_file);

}


async function update(req, res, query){



}

async function changeDNS(req, res, query){

    let new_dns = query.dns;

    if(Array.isArray(new_dns)) {
        try {
            let f2 = await fs.readFileSync(serverConfFile, "utf8");
            let ov_ns = f2.split("\n");
            let _file = "";
            for (let i = 0; i < ov_ns.length; i++) {
                if (ov_ns[i].trim().length > 0)
                    if (ov_ns[i].substr(0, 21) !== "push \"dhcp-option DNS") {
                        _file += ov_ns[i] + "\n";
                    }
            }

            for (let i = 0; i < new_dns.length; i++) {
                _file += "push \"dhcp-option DNS " + new_dns[i] + "\"\n";
            }

            await fs.writeFileSync(serverConfFile, _file);

        } catch (e) {
            console.log(e);
        }

        try {
            let _file = "";
            for (let i = 0; i < new_dns.length; i++) {
                _file += "nameserver " + new_dns[i] + "\n";
            }

            await fs.writeFileSync(resolveConfFile, _file);

        } catch (e) {
            console.log(e);
        }

        try{
            shell.exec("systemctl restart openvpn");
        }catch (e) {

        }
    }

}