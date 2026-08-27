package com.yuuki.poirot.utils;

import android.app.Activity;
import android.content.Context;
import android.graphics.Color;
import android.os.Build;
import android.view.View;
import android.view.Window;

public class Miscellaneous {

    public static void setFullImmersive(Activity activity) {
        Window window = activity.getWindow();

        window.setStatusBarColor(Color.TRANSPARENT);
        window.setNavigationBarColor(Color.TRANSPARENT);

        int flags = View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN |
                View.SYSTEM_UI_FLAG_LAYOUT_STABLE |
                View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION |
                View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            flags |= View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
        }

        window.getDecorView().setSystemUiVisibility(flags);
    }

    public static void setViewTopPadding(View rootView, Context context){
        rootView.setPadding(
                rootView.getPaddingLeft(),
                rootView.getPaddingTop() + getStatusBarHeight(context),
                rootView.getPaddingRight(),
                rootView.getPaddingBottom()
        );

    }

    public static int getStatusBarHeight(Context context) {
        int result = 0;
        int resourceId = context.getResources().getIdentifier("status_bar_height", "dimen", "android");
        if (resourceId > 0) {
            result = context.getResources().getDimensionPixelSize(resourceId);
        }
        return result;
    }
}
