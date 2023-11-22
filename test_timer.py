import timerList

timer = timerList.TimerList(1,1)
timer.start_timer(0)

while True:
    if len(timer.get_timed_out_timers()) == 1:
        print("timeout")
        timer = timerList.TimerList(1,1)
        timer.start_timer(0)