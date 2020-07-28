const fs = require("fs");
const path = require("path");
const cron = require("node-cron");
const fetch = require("node-fetch");
const admin = require("firebase-admin");
const { v4: uuidv4 } = require("uuid");
const express = require("express");
const favicon = require("serve-favicon");
const session = require("express-session");
const FirestoreStore = require("firestore-store")(session);
const dotenv = require("dotenv");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
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

passport.serializeUser((user, done) => done(null, user));

passport.deserializeUser((user, done) => done(null, user));

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

// custom parser for session store
// adds dateModified field so we can prune old ones
const parser = {
  read: doc => JSON.parse(doc.session),
  save: doc => {
    return {
      session: JSON.stringify(doc),
      dateModified: new Date()
    };
  }
};

app.enable("trust proxy"); // required when running on Heroku as SSL terminates before reaching express
app.use(favicon(path.join(__dirname, "favicon.ico")));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    store: new FirestoreStore({
      parser,
      database: firestore,
      collection: "authSessions"
    }),
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    proxy: true, // required when running on Heroku as SSL terminates before reaching express
    cookie: {
      secure: true,
      maxAge: 25 * 60 * 1000
    }
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

const mapKerberosFields = kerberosData => {
  return {
    firstName: kerberosData["urn:oid:2.5.4.42"],
    lastName: kerberosData["urn:oid:2.5.4.4"],
    email: kerberosData.email,
    affiliations: kerberosData["urn:oid:1.3.6.1.4.1.5923.1.1.1.1"],
    primaryAffiliation: kerberosData["urn:oid:1.3.6.1.4.1.5923.1.1.1.5"],
    organization: kerberosData["urn:oid:2.5.4.10"]
  };
};

// generates a firebase token, tied to the uid that matches the sso email
const generateToken = async user => {
  const { email } = user;
  const uid = await fetchUID(email);
  const additionalClaims = { ...user }; // include sso data so auth rules can access it

  // only update user and db if this is the first time (email verified is false)
  const { emailVerified } = await admin
    .auth()
    .getUser(uid)
    .catch(error => {
      if (error.code === "auth/user-not-found") {
        return admin
          .auth()
          .createUser({ uid })
          .catch(console.error);
      } else console.error(error);
    });

  if (!emailVerified) {
    await admin
      .auth()
      .updateUser(uid, {
        displayName: `${user.firstName} ${user.lastName}`,
        email,
        emailVerified: true
      })
      .catch(console.error);

    await firestore.doc(`users/${uid}`).update(user);
  }

  return admin
    .auth()
    .createCustomToken(uid, additionalClaims)
    .then(customToken => customToken)
    .catch(error => console.error("Error creating custom token:", error));
};

app.post("/generateUIDs", (req, res) => {
  const { emails } = req.body;
  const fetchUIDs = emails.map(email => fetchUID(email));
  Promise.all(fetchUIDs).then(uids => {
    const mapped = uids.map((uid, i) => {
      return {
        email: emails[i],
        uid
      };
    });

    res.json(mapped);
  });
});

app.get("/", saveReferrer, ensureAuthenticated, async (req, res) => {
  console.log("hitting root")
  const token = await generateToken(mapKerberosFields(req.user));
  res.redirect(`${req.session.referrer}?token=${token}`);
});

app.get(
  "/login",
  passport.authenticate("saml", { failureRedirect: "/login/fail" }),
  (req, res) => res.redirect("/")
);

app.post(
  "/login/callback",
  passport.authenticate("saml", { failureRedirect: "/login/fail" }),
  (req, res) => {
    console.log("successful callback")
    console.log(req.user)
    res.redirect("/");
  }
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

app.get("/keepalive", (req, res) => res.send("Alive"));

// general error handler
app.use((err, req, res, next) => {
  console.error("Fatal error: " + JSON.stringify(err));
  next(err);
});

const serverPort = process.env.PORT || 3030;
app.listen(serverPort, () => console.log(`Listening on port ${serverPort}`));

console.log(`Starting keepalive for ${process.env.KEEPALIVE_URL}`);
cron.schedule("0 */25 * * * *", () => {
  fetch(process.env.KEEPALIVE_URL)
    .then(res =>
      console.log(`Keepalive: response-ok: ${res.ok}, status: ${res.status}`)
    )
    .catch(console.error);

  console.log("Pruning authSessions...");
  const now = new Date();
  const pruneTime = new Date(now.getTime() - 25 * 60000);
  firestore
    .collection("authSessions")
    .where("dateModified", "<", pruneTime)
    .get()
    .then(querySnapshot =>
      querySnapshot.forEach(snapshot => snapshot.ref.delete())
    );
});
