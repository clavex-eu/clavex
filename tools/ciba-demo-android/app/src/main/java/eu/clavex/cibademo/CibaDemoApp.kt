package eu.clavex.cibademo

import android.app.Application
import com.google.firebase.FirebaseApp

class CibaDemoApp : Application() {
    override fun onCreate() {
        super.onCreate()
        FirebaseApp.initializeApp(this)
    }
}
