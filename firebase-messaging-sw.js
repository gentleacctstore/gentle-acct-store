
importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-messaging-compat.js');

firebase.initializeApp({
  apiKey: "AIzaSyAhF6gcjPMqaHA5d1ZlKbaJdDBXOqGPlrg",
  authDomain: "gentle-acct-store.firebaseapp.com",
  projectId: "gentle-acct-store",
  storageBucket: "gentle-acct-store.firebasestorage.app",
  messagingSenderId: "210301738694",
  appId: "1:210301738694:web:6e37cac47b0eacc68d01c7"
});

const messaging = firebase.messaging();

messaging.onBackgroundMessage((payload) => {
  const title = payload.notification?.title || 'Gentle Acct Store';

  const options = {
    body: payload.notification?.body || 'You have a new notification',
    icon: '/favicon.ico'
  };

  self.registration.showNotification(title, options);
});
