const fs = require("fs");
const admin = require("firebase-admin");
const { v4: uuidv4 } = require("uuid");
const express = require("express");
const dotenv = require("dotenv");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const passport = require("passport");
const SamlStrategy = require("passport-saml").Strategy;

dotenv.config();

admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: JSON.parse(`"${process.env.FIREBASE_PRIVATE_KEY}"`)
  }),
  databaseURL: process.env.FIREBASE_DATABASE_URL
});

const firestore = admin.firestore();

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

const SamlOptions = {
  // URL that goes from the Identity Provider -> Service Provider
  callbackUrl: process.env.CALLBACK_URL,
  // URL that goes from the Service Provider -> Identity Provider
  entryPoint: process.env.ENTRY_POINT,
  // Usually specified as `/shibboleth` from site root
  issuer: process.env.ISSUER,
  identifierFormat: null,
  validateInResponseTo: false,
  disableRequestedAuthnContext: true
};

// Service Provider private key
if (process.env.SHIBBOLETH_KEY) {
  SamlOptions.decryptionPvk = JSON.parse(`"${process.env.SHIBBOLETH_KEY}"`);
  SamlOptions.privateCert = JSON.parse(`"${process.env.SHIBBOLETH_KEY}"`);
} else {
  SamlOptions.decryptionPvk = fs.readFileSync(
    __dirname + "/cert/key.pem",
    "utf8"
  );
  SamlOptions.privateCert = fs.readFileSync(
    __dirname + "/cert/key.pem",
    "utf8"
  );
}

// Identity Provider's public key
if (process.env.SHIBBOLETH_IDP_CERT) {
  SamlOptions.cert = JSON.parse(`"${process.env.SHIBBOLETH_IDP_CERT}"`);
} else {
  SamlOptions.cert = fs.readFileSync(__dirname + "/cert/cert_idp.pem", "utf8");
}

const samlStrategy = new SamlStrategy(SamlOptions, (profile, done) =>
  done(null, profile)
);
passport.use(samlStrategy);

const app = express();

app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: { secure: true }
  })
);
app.use(passport.initialize());
app.use(passport.session());

// saves request referrer to session storage before initiating login
const saveReferrer = (req, res, next) => {
  req.session.referrer = req.get("Referrer");
  return next();
};

// makes sure user is authenticated before forwarding to route
const ensureAuthenticated = (req, res, next) => {
  console.log("auth?", req.isAuthenticated());
  console.log("user?", req.user);
  if (req.isAuthenticated()) return next();
  else return res.redirect("/login");
};

// checks firestore for uid, if not it creates one for the future
const fetchUID = email => {
  const doc = firestore.doc(`uids/${email}`);
  return doc.get().then(async snapshot => {
    const data = snapshot.data();
    let uid = null;
    if (data) uid = data.value;
    if (uid === null) {
      uid = uuidv4();
      await doc.set({ value: uid });
    }

    return uid;
  });
};

// generates a firebase token, tied to the uid that matches the sso email
const generateToken = async ssoData => {
  console.log(ssoData);
  const email = ssoData[email];
  const uid = await fetchUID(email);
  const additionalClaims = { ...ssoData }; // include sso data so client apps can access it

  return admin
    .auth()
    .createCustomToken(uid, additionalClaims)
    .then(customToken => customToken)
    .catch(error => console.log("Error creating custom token:", error));
};

app.get("/", ensureAuthenticated, async (req, res) => {
  res.send('Authenticated!');
});

app.get("/token", saveReferrer, ensureAuthenticated, async (req, res) => {
  const token = await generateToken(req.user);
  res.header("Set-Cookie", `firebase-token=${token}; Max-Age=60`); // ; Secure
  res.redirect(`${req.session.referrer}login/callback`);
});

app.get(
  "/login",
  passport.authenticate("saml", { failureRedirect: "/login/fail" }),
  (req, res) => res.redirect("/")
);

app.post(
  "/login/callback",
  passport.authenticate("saml", { failureRedirect: "/login/fail" }),
  (req, res) => res.redirect("/")
);

app.get("/login/fail", (req, res) => res.status(401).send("Login failed"));

app.get("/shibboleth/metadata", (req, res) => {
  res.type("application/xml");
  let cert = null;
  if (process.env.SHIBBOLETH_CERT) {
    cert = JSON.parse(`"${process.env.SHIBBOLETH_CERT}"`);
  } else {
    cert = fs.readFileSync(__dirname + "/cert/cert.pem", "utf8");
  }
  res
    .status(200)
    .send(samlStrategy.generateServiceProviderMetadata(cert, cert));
});

// general error handler
app.use(function(err, req, res, next) {
  console.error("Fatal error: " + JSON.stringify(err));
  next(err);
});

const serverPort = process.env.PORT || 3030;
app.listen(serverPort, () => console.log(`Listening on port ${serverPort}`));
