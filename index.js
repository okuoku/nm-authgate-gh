const Provider = require("oidc-provider");
const Koa = require("koa");
const KoaMount = require("koa-mount");
const KoaRouter = require("koa-router");
const KoaEjs = require("koa-ejs");
const Jose = require("jose");
const Yaml = require("js-yaml");
const Fetch = require("node-fetch");
const crypto = require("crypto");
const path = require("path");
const url = require("url");
const fs = require("fs");
const LRU = require("lru-cache");
const VolatileAdapter = require("./volatileadapter.js");
const DummyCookieKeys = new Array(crypto.randomBytes(32).toString("base64"));

const keystore = new Jose.JWKS.KeyStore();
keystore.generateSync("RSA", 4096, { alg: "RS256", use: "sig" });
const keystore_jwks = keystore.toJWKS(true);

const configpath = process.env.CONFIG_PATH ? process.env.CONFIG_PATH : __dirname + "/config.yaml";
const config = Yaml.safeLoad(fs.readFileSync(configpath, "utf8"));

const myurl = new URL(config.host.url);
const webroot = myurl.pathname;
const weburl = myurl.href;

const port = process.env.PORT ? process.env.PORT : myurl.port;

const github = config.github;
const gh_instance = github.instance;
const gh_api_instance = github.api_instance;
const gh_client_id = github.client_id;
const gh_client_secret = github.client_secret;
const siteprefix = config.host.siteprefix;

const issroot = weburl + "op";
const gh_redirect_uri = weburl + "gate/callback";

const ejs_config = {
    root: path.join(__dirname, "view"),
    layout: "_base",
    viewExt: "html",
    cache: true,
    debug: false
};

const store = new LRU({});

// FIXME: protect with nonce
function save_userinfo(sid, obj){
    store.set(sid, obj, 30*1000);
}

// FIXME: protect with nonce
function load_userinfo(sid){
    return store.get(sid);
}


const oidc_config = {
    adapter: VolatileAdapter,
    jwks: keystore_jwks,
    findAccount: (ctx, id) => {
        const userinfo = load_userinfo(id);
        let out = {sub: id};
        //console.log("FindAccount", id);
        if(userinfo){
            if(userinfo.access_token){
                out.xm_access_token = userinfo.access_token;
            }
            if(userinfo.profile){
                out.profile = userinfo.profile;
            }
            if(userinfo.picture){
                out.picture = userinfo.picture;
            }
            if(userinfo.username){
                out.preferred_username = userinfo.username;
            }
            if(userinfo.groups){
                out.groups = userinfo.groups;
            }
        }
        
        return {
            accountId: id,
            claims: (use, scope) => Promise.resolve(out)
        };
    },
    features: {
        introspection: {enabled: true},
        devInteractions: {enabled: false}
    },
    formats: {
        AccessToken: "jwt"
    },
    clients: [config.client],
    interactions: {
        url: (ctx, interaction) => Promise.resolve(webroot + "gate?uid=" + 
        ctx.oidc.uid)
    },
    cookies: {
        keys: DummyCookieKeys,
        short: {signed: true},
        long: {signed: true}
    },
    // Custom id_token claim(s)
    claims: {
        // Standard claims
        acr: null,
        iss: null,
        auth_time: null,
        sid: null,
        openid: [
            "sub", "preferred_username", "profile", "picture", 
            // Source ??
            "groups",
            // Yuniauth extention: xm_access_token, xm_refresh_token
            "xm_access_token", "xm_refresh_token"
        ]
    }
};

const oidc = new Provider(issroot, oidc_config);

async function gate(ctx, next){
    // Redirect to Github
    // FIXME: Implement `state` value

    const uri = url.format({protocol: "https",
                           host: gh_instance,
                           pathname: "/login/oauth/authorize",
                           query: {
                               client_id: gh_client_id,
                               redirect_uri: gh_redirect_uri + "/" + 
                               ctx.request.query.uid,
                               scope: "user repo",
                               allow_signup: "false"
                           }});
    ctx.redirect(uri);
}

function gh_getuser(token){
    const uri = url.format({protocol: "https",
                           host: gh_api_instance,
                           pathname: "/user",
                           query: {}});
    return Fetch(uri, {
        method: "GET",
        headers: {
            "Authorization": "token " + token,
            "Accept": "application/json"
        }}).then(res => {
            if(res.ok){
                return res.json();
            }else{
                console.log(res);
                return Promise.resolve(false);
            }
        })
}

function gh_getorgs(token){
    const uri = url.format({protocol: "https",
                           host: gh_api_instance,
                           pathname: "/user/orgs",
                           query: {per_page: 300}});
    return Fetch(uri, {
        method: "GET",
        headers: {
            "Authorization": "token " + token,
            "Accept": "application/json"
        }}).then(res => {
            if(res.ok){
                return res.json();
            }else{
                console.log(res);
                return Promise.resolve(false);
            }
        })
}

async function gh_callback(ctx, next){
    //const details = await oidc.interactionDetails(ctx.req, ctx.res);

    //console.log("Current", details);

    const authcode = ctx.query.code;
    // FIXME: Implement `state` value
    const uri = url.format({protocol: "https",
                           host: gh_instance,
                           pathname: "/login/oauth/access_token",
                           query: {
                               client_id: gh_client_id,
                               client_secret: gh_client_secret,
                               code: authcode
                           }});
    // Exchange code to access token
    const tokenobj = await Fetch(uri, {
        method: "POST",
        headers: {
            "Accept": "application/json",
        }
    }).then(res => {
        if(res.ok){
            return res.json();
        }else{
            return Promise.resolve(false);
        }
    });

    //console.log("Token", tokenobj);

    const token = tokenobj.access_token;

    // Get User data
    // https://developer.github.com/v3/users/#get-the-authenticated-user
    const userdata = await gh_getuser(token);
    const orgdata = await gh_getorgs(token);
    let userinfo = {};
    //console.log("User", userdata);
    //console.log("orgdata", orgdata);
    const sid = siteprefix + ":" + userdata.id.toString();
    //console.log("Sid", sid);

    userinfo.access_token = token;
    if(orgdata){
        userinfo.groups = orgdata.map(e => e.login);
    }
    userinfo.username = userdata.login;
    userinfo.picture = userdata.avatar_url;
    userinfo.profile = userdata.html_url;

    save_userinfo(sid, userinfo);

    const result = {
        login: {
            account: sid,
            acr: "0",
            remember: false,
        },
        consent: {
            rejectedScopes: [],
            rejectedClaims: []
        }
    };

    try {
        return oidc.interactionFinished(ctx.req, ctx.res, result);
    } catch (e) {
        console.log(e);
    }
}


const app = new Koa();
const router = new KoaRouter();

// NB: Cookies will have `/gate` address
router.get(webroot + "gate/callback/:uid", gh_callback); 
router.get(webroot + "gate", gate);
app.use(router.routes())
   .use(router.allowedMethods());

KoaEjs(app, ejs_config);
app.use(KoaMount(webroot + "op", oidc.app));

app.proxy = true;

console.log("LISTEN", port);
app.listen(port);
