// Firebase connection for Gentle Acct Store

const firebaseConfig = {
  apiKey: "AIzaSyAhF6gcjPMqaHA5d1ZlKbaJdDBXOqGPlrg",
  authDomain: "gentle-acct-store.firebaseapp.com",
  projectId: "gentle-acct-store",
  storageBucket: "gentle-acct-store.firebasestorage.app",
  messagingSenderId: "210301738694",
  appId: "1:210301738694:web:6e37cac47b0eacc68d01c7",
  measurementId: "G-FN045CZYZG"
};


// =========================
// START FIREBASE
// =========================

firebase.initializeApp(firebaseConfig);


// =========================
// FIREBASE AUTHENTICATION
// =========================

window.firebaseAuth =
  firebase.auth();


// =========================
// CLOUD FIRESTORE
// =========================

/*
  Firestore will be available
  on pages that load the
  Firebase Firestore SDK.
*/

if (
  typeof firebase.firestore === "function"
) {
  
  window.firebaseDB =
    firebase.firestore();
  
}