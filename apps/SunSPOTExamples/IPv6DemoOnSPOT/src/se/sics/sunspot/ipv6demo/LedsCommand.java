/*
 * Copyright (c) 2009, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: LedsCommand.java 28 2009-06-06 14:16:16Z joakime $
 *
 * -----------------------------------------------------------------
 *
 * LedsCommand
 *
 * Authors : Joakim Eriksson, Niclas Finne
 * Created : 6 jun 2009
 * Updated : $Date: 2009-06-06 16:16:16 +0200 (Sat, 06 Jun 2009) $
 *           $Revision: 28 $
 */

package se.sics.sunspot.ipv6demo;
import com.sun.spot.sensorboard.EDemoBoard;
import com.sun.spot.sensorboard.peripheral.ITriColorLED;
import se.sics.sunspot.cli.BasicCommand;
import se.sics.sunspot.cli.CommandContext;

/**
 *
 */
public class LedsCommand extends BasicCommand {

  private final ITriColorLED[] leds = EDemoBoard.getInstance().getLEDs();

  public LedsCommand() {
    super("set the leds", "[led] [RGB]");
  }

  public int executeCommand(CommandContext context) {
    if(context.getArgumentCount() == 0) {
      context.out.println("LEDS:");
      for (int i = 0, n = leds.length; i < n; i++) {
        context.out.println(" " + (i + 1) + ": " + leds[i].getRed() + "," +
            leds[i].getGreen() + "," + leds[i].getBlue() + " " + (leds[i].isOn() ? "on" : "off"));
      }
    } else {
      int index = context.getArgumentAsInt(0);
      int color = 0;
      if (context.getArgumentCount() > 1) {
        color = context.getArgumentAsInt(1);
      }
      for (int i = 0, n = leds.length; i < n; i++) {
        if ((index & (1 << i)) != 0) {
          if (color <= 0) {
            leds[i].setOff();
          } else {
            leds[i].setRGB((color >> 16) & 0xff, (color >> 8) & 0xff, color & 0xff);
            leds[i].setOn();
          }
        }
      }
    }
    return 0;
  }

}
