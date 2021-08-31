import express, { RequestHandler } from "express";
import crypto from "crypto";
import compression from "compression";
import helmet from "helmet";
import cors from "cors";
import tiny from "tiny-json-http";

import { AuthorizationCode } from "simple-oauth2";
const client_id = process.env.OAUTH_CLIENT_ID;
const client_secret = process.env.OAUTH_CLIENT_SECRET;
const authUrl = `https://github.com/login/oauth/authorize?client_id=${client_id}&scope=repo,user`;
const tokenUrl = "https://github.com/login/oauth/access_token";


const PORT = process.env.PORT ?? 4000;

const app = express();

app.use(function (req, res, next) {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; font-src 'self'; img-src 'self'; script-src 'inline-src'; style-src 'self'; frame-src 'self'"
  );
  next();
});


const redirect_uri =
  process.env.REDIRECT_URI ?? "http://localhost:4000/callback";
const scope = process.env.SCOPE ?? "";
const provider = process.env.PROVIDER ?? "github";
const originPattern = process.env.ORIGIN ?? "";


if ("".match(originPattern)) {
  console.warn(
    "Insecure ORIGIN pattern used. This can give unauthorized users access to your repository."
  );
  if (process.env.NODE_ENV === "production") {
    console.error("Will not run without a safe ORIGIN pattern in production.");
    process.exit();
  }
}

const client = new AuthorizationCode({
  client: {
    id: process.env.OAUTH_CLIENT_ID!,
    secret: process.env.OAUTH_CLIENT_SECRET!,
  },
  auth: {
    tokenHost: "https://github.com",
    tokenPath: "/login/oauth/access_token",
    authorizePath: "/login/oauth/authorize",
  },
});

/**
 * Redirects to providers authorization endpoint
 *
 * @param req {Express.RequestRequest}
 * @param res {Express.Response}
 */
export const auth: RequestHandler = (req, res) => {
  const authorizeUri = client.authorizeURL({
    redirect_uri,
    scope,
    state: crypto.randomBytes(16).toString("hex"),
  });

  res.redirect(authorizeUri);
};

/**
 * Fetches token from provider and emulates NetlifyCMS authentication script
 *
 * @param req {Express.Request}
 * @param res {Express.Request}
 * @returns {Express.Response}
 */
export const callback: RequestHandler = async (req, res) => {
  const data = {
    code: req.query.code,
    client_id,
    client_secret
  };

  try {
    const { body } = await tiny.post({
      url: tokenUrl,
      data,
      headers: {
        // GitHub returns a string by default, ask for JSON to make the reponse easier to parse.
        "Accept": "application/json"
      }
    });

    const postMsgContent = {
      token: body.access_token,
      provider: "github"
    };

    // This is what talks to the NetlifyCMS page. Using window.postMessage we give it the
    // token details in a format it's expecting
    const script = `
    <script>
    (function() {
      function recieveMessage(e) {
        console.log("recieveMessage %o", e);
        
        // send message to main window with the app
        window.opener.postMessage(
          'authorization:github:success:${JSON.stringify(postMsgContent)}', 
          e.origin
        );
      }
      window.addEventListener("message", recieveMessage, false);
      window.opener.postMessage("authorizing:github", "*");
    })()
    </script>`;

    return res.send(script);

  } catch (err) {
    // If we hit an error we'll handle that here
    console.log(err);
    res.redirect("/?error=😡");
  }
}




// Adds a nonce to response for use on inline scripts
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString("hex");
  next();
});

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        // @ts-expect-error res is of class ServerResponse from http module not express Response. Havent found a way to extend ServerResponse
        "script-src": ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`],
      },
    },
  })
);
app.use(cors());
app.use(
  compression({
    level: 6,
  })
);
app.use(express.json());

const BROWSER_MAX_AGE = 60 * 60;
const CDN_MAX_AGE = 60 * 60 * 24;
const cache: RequestHandler = (req, res, next) => {
  res.set(
    "cache-control",
    `public, max-age=${BROWSER_MAX_AGE}, s-maxage=${CDN_MAX_AGE}`
  );
  next();
};


//app.get("/", (_, res) => res.json({ status: "OK 123" }));




app.get("/", (req, res) => {
  res.send(`<a href="${authUrl}">Login with Github</a>`);
});
// Auth routes for CMS
app.get("/auth", auth);
app.get("/callback", callback);

app.listen(PORT, () => {
  console.log(`API listening at http://localhost:${PORT}`);
});