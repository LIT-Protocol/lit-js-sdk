import firebase from 'firebase/app'
import 'firebase/functions'

const firebaseConfig = {
  apiKey: 'AIzaSyDa3JnwzrjfY5DcPz4GtywdUUUY3zqWo0w',
  authDomain: 'mintlit.firebaseapp.com',
  projectId: 'mintlit',
  storageBucket: 'mintlit.appspot.com',
  messagingSenderId: '1044454922569',
  appId: '1:1044454922569:web:a3cf1d5637f18413f66298',
  measurementId: 'G-NC19HWVQPT'
}

// Initialize Firebase
firebase.initializeApp(firebaseConfig)

export default firebase
