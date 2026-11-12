package dev.zeroemu.sdtest;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import java.io.File;
import java.io.FileOutputStream;

/** Writes a file into its external files directory (/sdcard/Android/data/<pkg>/files) and logs the outcome. */
public class Main extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        try {
            File dir = getExternalFilesDir(null);
            File f = new File(dir, "hello.txt");
            try (FileOutputStream out = new FileOutputStream(f)) {
                out.write(("written by uid " + android.os.Process.myUid() + "\n").getBytes());
            }
            Log.i("sdtest", "wrote " + f + " " + f.length());
        } catch (Exception e) {
            Log.e("sdtest", "failed", e);
        }
        finish();
    }
}
