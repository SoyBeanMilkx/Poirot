package com.yuuki.poirot;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;

import com.yuuki.poirot.utils.Miscellaneous;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {
	private final ExecutorService detector = Executors.newSingleThreadExecutor();
	private TextView output;
	private Button run;

    static {
        System.loadLibrary("poirot");
    }

	private native String nativeDescribe();
	private native String nativeRunDetection();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Miscellaneous.setFullImmersive(this);
        setContentView(R.layout.activity_main);
        Miscellaneous.setViewTopPadding(findViewById(R.id.root), this);

		output = findViewById(R.id.show);
		run = findViewById(R.id.run);
		output.setText(nativeDescribe());
		run.setOnClickListener(view -> runDetection());
    }

	private void runDetection() {
		run.setEnabled(false);
		output.setText("Running probes…");
		detector.execute(() -> {
			String report = nativeRunDetection();
			runOnUiThread(() -> {
				output.setText(report);
				run.setEnabled(true);
			});
		});
	}

	@Override
	protected void onDestroy() {
		detector.shutdownNow();
		super.onDestroy();
	}

}
