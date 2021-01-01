import turtle
import random
from math import cos, sin, atan2, radians, degrees 
import base64

alphabet = {'A':((0, 0), (0.5, 1), (0.75, 0.5), (0.25, 0.5), (0.75, 0.5), (1, 0)),  'B':((0, 0), (0, 1), (0.625, 1), (0.75, 0.875), (0.75, 0.625), (0.625, 0.5), (0, 0.5),
 (0.625, 0.5), (0.75, 0.375), (0.75, 0.125), (0.625, 0), (0, 0)),
 'C':((0.75, 0.125), (0.625, 0), (0.125, 0), (0, 0.125), (0, 0.875), (0.125, 1), (0.625, 1),
 (0.75, 0.875)),
 'D':((0, 0), (0, 1), (0.625, 1), (0.75, 0.875), (0.75, 0.125), (0.625, 0), (0, 0)),
 'E':((0.75, 0), (0, 0), (0, 0.5), (0.75, 0.5), (0, 0.5), (0, 1), (0.75, 1)),
 'F':((0, 0), (0, 0.5), (0.75, 0.5), (0, 0.5), (0, 1), (0.75, 1)),
 'G':((0.75, 0.5), (0.625, 0.5), (0.75, 0.5), (0.75, 0.125), (0.625, 0), (0.125, 0), (0, 0.125),
 (0, 0.875), (0.125, 1), (0.625, 1), (0.75, 0.875)),
 'H':((0, 0), (0, 1), (0, 0.5), (0.75, 0.5), (0.75, 1), (0.75, 0)),
 'I':((0, 0), (0.25, 0), (0.125, 0), (0.125, 1), (0, 1), (0.25, 1)),
 'J':((0, 0.125), (0.125, 0), (0.375, 0), (0.5, 0.125), (0.5, 1)),
 'K':((0, 0), (0, 1), (0, 0.5), (0.75, 1), (0, 0.5), (0.75, 0)),
 'L':((0, 0), (0, 1), (0, 0), (0.75, 0)),
 'M':((0, 0), (0, 1), (0.5, 0), (1, 1), (1, 0)),
 'N':((0, 0), (0, 1), (0.75, 0), (0.75, 1)),
 'O':((0.75, 0.125), (0.625, 0), (0.125, 0), (0, 0.125), (0, 0.875), (0.125, 1), (0.625, 1),
 (0.75, 0.875), (0.75, 0.125)),
 'P':((0, 0), (0, 1), (0.625, 1), (0.75, 0.875), (0.75, 0.625), (0.625, 0.5), (0, 0.5)),
 'Q':((0.75, 0.125), (0.625, 0), (0.125, 0), (0, 0.125), (0, 0.875), (0.125, 1), (0.625, 1),
 (0.75, 0.875), (0.75, 0.125), (0.875, 0)),
 'R':((0, 0), (0, 1), (0.625, 1), (0.75, 0.875), (0.75, 0.625), (0.625, 0.5), (0, 0.5),
 (0.625, 0.5), (0.875, 0)),
 'S':((0, 0.125), (0.125, 0), (0.625, 0), (0.75, 0.125), (0.75, 0.375), (0.675, 0.5), (0.125, 0.5),
 (0, 0.625), (0, 0.875), (0.125, 1), (0.625, 1), (0.75, 0.875)),
 'T':((0, 1), (0.5, 1), (0.5, 0), (0.5, 1), (1, 1)),
 'U':((0, 1), (0, 0.125), (0.125, 0), (0.625, 0), (0.75, 0.125), (0.75, 1)),
 'V':((0, 1), (0.375, 0), (0.75, 1)),
 'W':((0, 1), (0.25, 0), (0.5, 1), (0.75, 0), (1, 1)),
 'X':((0, 0), (0.375, 0.5), (0, 1), (0.375, 0.5), (0.75, 1), (0.375, 0.5), (0.75, 0)),
 'Y':((0, 1), (0.375, 0.5), (0.375, 0), (0.375, 0.5), (0.75, 1)),
 'Z':((0, 1), (0.75, 1), (0, 0), (0.75, 0))}


myPen = turtle.Turtle()
myPen.hideturtle()
myPen.speed(0)
window = turtle.Screen()
window.bgcolor("#000000")
myPen.pensize(2)

def displayMessage(message,fontSize,color,x,y,rotationAngle):
  myPen.color(color)
  message=message.upper()
  myPen.penup()
  myPen.goto(x,y)  
  for character in message:
    if character in alphabet:
      letter=alphabet[character]
      myPen.setheading(rotationAngle)
      myPen.penup()
    
      x=0
      y=0
      for dot in letter:
        angle = atan2((dot[1]-y),(dot[0]-x))
        angle= degrees(angle)    
  
        distance = ((dot[0]-x)**2 + (dot[1]-y)**2)**0.5
        myPen.setheading(rotationAngle)
  
        myPen.left(angle)
        myPen.forward(distance*fontSize)
        x = dot[0]
        y = dot[1]
        myPen.pendown()
  
      myPen.penup()
      angle = atan2((0-y),(0-x))
      angle = degrees(angle)    
  
      distance = ((0-x)**2 + (0-y)**2)**0.5
      myPen.setheading(rotationAngle)
  
      myPen.left(angle)
      myPen.forward(distance*fontSize)
  
    myPen.setheading(rotationAngle)
    myPen.penup()
    myPen.forward(fontSize)    
    
    myPen.forward(characterSpacing)
    

#Main Program Starts Here
fontSize = 30
fontColor="#FF00FF"
characterSpacing = 5
cursorX = -250
cursorY = -100

message = ''.join([ chr(int(n)-1) for n in base64.b64decode("ODMgNzAgODQgODUgNjggODAgNzkgMTI0IDExNyAxMTggMTE1IDExNyAxMDkgMTAyIDk2IDEwNiAxMTYgOTYgMTAwIDExMiAxMTIgMTA5IDEyNiA=".encode("ascii")).decode("ascii").split(" ")[:-1]])
rotationAngle=90
myPen.goto(cursorX,cursorY)

for character in message:
  pos=myPen.position()
  displayMessage(character,fontSize,fontColor,pos[0],pos[1],rotationAngle)
  rotationAngle-=180/(len(message)-1)
