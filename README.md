# BU UPE Authenticator

This server authenticates users with BU Kerberos and returns a Firebase token that can be used with our various Firebase applications (main website, interview tool, etc).

## How to Connect

To use this authentication server in a new Firebase project, first make sure that project is using the "UPE Master" Firebase instance. Then, add a link (anchor tag) somewhere on your site that lands on Authenticator's root ([https://upe-authenticator.herokuapp.com/](https://upe-authenticator.herokuapp.com/)). Finally, make sure your app has a route for `https://yourapp.com/login/callback`, as Authenticator will redirect there upon successful login through BU Kerberos. At `https://yourapp.com/login/callback`, check for the existence of the `firebase-token` cookie, and use that token to login like so:

```
firebase.auth().signInWithCustomToken(token).catch(function(error) {
  // Handle Errors here.
  var errorCode = error.code;
  var errorMessage = error.message;
  // ...
});
```

If the `firebase-token` cookie does not exist, show the user some error message so they can try again.

## Testing Locally

Clone the repo, copy `.env.example` to `.env` and fill out appropriately, then run:

```
yarn install
yarn start
```
