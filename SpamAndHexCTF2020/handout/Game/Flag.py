completionTimes = [1330, 1560, 1790, 2020, 2250]

def printFlag(num, time):
  if num == 0:
    print("You beat the game! Here's flag number %d:" % num, flush=True)
  else:
    print("You beat the game under %d frames! Here's flag number %d:"
          % (time, num), flush=True)
  try:
    with open('../flag%d.txt' % num, 'r') as file:
      flag = file.read().strip()
      print(flag, flush=True)
  except:
    print("...is what I'd say if you had bothered to create a flag file >:(", flush=True)


def printFlags(time):
  print("Your time: %d frames" % time, flush=True)
  i = 0
  printFlag(0, 0)
  for t in completionTimes[::-1]:
    i += 1
    if time < t:
      printFlag(i, t)
    else:
      print("Now try completing it under %d frames!" % t, flush=True)
      break
