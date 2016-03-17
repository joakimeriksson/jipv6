package se.sics.sunspot.ipv6demo;

import com.sun.spot.sensorboard.EDemoBoard;
import com.sun.spot.sensorboard.peripheral.IAccelerometer3D;
import com.sun.spot.sensorboard.peripheral.ITriColorLED;

import se.sics.sunspot.cli.BasicAsyncCommand;
import se.sics.sunspot.cli.CommandContext;

public class SenseCommand extends BasicAsyncCommand implements Runnable {
    private boolean exit = false;
    private int sleep;
    private CommandContext context;
    private final IAccelerometer3D accelerometerSensor = EDemoBoard.getInstance().getAccelerometer();
    private final ITriColorLED[] leds = EDemoBoard.getInstance().getLEDs();

    public SenseCommand() {
        super("read sensors regularly", "msek");
    }

    public int executeCommand(CommandContext context) {
        if (context != null) {
            //sleep = context.getArgumentAsInt(0);
            sleep = 100;
            /* 100 msek as default interval */
            this.context = context;
            new Thread(this).start();
            return 0;
        } else {
            context.out.println("Can not start more than one sense command");
            return 1;
        }
    }

    public void run() {
        boolean play = true;
        int nextDelay = 0;
        int led = 0;
        while(!exit) {
            try {
                double x = accelerometerSensor.getAccelX();
                double y = accelerometerSensor.getAccelY();
                double z = accelerometerSensor.getAccelZ();
                Thread.sleep(sleep);

                led = (led + 1) & 7;
                if (play) {
                    leds[led].setRGB(0, 255, 0);
                    leds[led].setOn();
                } else if (led == 4) {
                    for (int i = 0; i < 8; i++) {
                        leds[i].setRGB(255, 0, 0);
                    }
                }
                for (int i = 0; i < 8; i++) {
                    leds[i].setRGB((int) (leds[i].getRed() / 2),
                            (int) (leds[i].getGreen() / 2),
                            (int) (leds[i].getBlue() / 2));
                }

                if (z < -0.2 && play) {
                    send("stop");
                    play = false;
                }
                if (z > 0.2 && !play) {
                    send("play");
                    play = true;
                }
                if (y > 0.5 && nextDelay == 0) {
                    nextDelay = 25;
                    send("next");
                    for (int i = 0; i < 8; i++) {
                        leds[i].setOn();
                        leds[i].setRGB(255, 255, 0);
                        Thread.sleep(5);
                    }
                    for (int i = 0; i < 8; i++) {
                        leds[i].setOff();
                        Thread.sleep(5);
                    }
                }
                if (nextDelay > 0) nextDelay--;
                //context.out.println("" + x + "," + y + "," + z);
            } catch (Exception e) {
            }
        }
    }

    private void send(String cmd) {
        context.out.println(cmd);
        context.out.flush();
    }

    public void stopCommand(CommandContext context) {
        exit = true;
    }
}
