
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

// Initialize Firebase safely
if (!firebase.apps.length) {
  firebase.initializeApp(firebaseConfig);
}

// Firebase Authentication
window.firebaseAuth = firebase.auth();

// Cloud Firestore
window.firebaseDB = firebase.firestore();

// Firebase Messaging
window.firebaseMessaging = null;

if (
  typeof firebase.messaging === "function" &&
  typeof window !== "undefined" &&
  "serviceWorker" in navigator
) {
  try {
    window.firebaseMessaging = firebase.messaging();
  } catch (error) {
    console.warn("Firebase Messaging unavailable:", error);
  }
}

console.log("Gentle Acct Store Firebase initialized successfully.");
