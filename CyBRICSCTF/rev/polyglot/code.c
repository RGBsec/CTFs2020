#include <stdlib.h>
#include <stdio.h>
#include <string.h>
char flagged[] = {78,6,10,80,30,69,0,68,77,83,13,92,1,68,22,68,12,2,90,62,120,68,1,76,29,3,5,71,23,16,88,84,3,28,13,84,28,85,0,1,4,1,16,19,19,28,68,84,3,28,13,84,28,85,0,1,4,1,16,19,16,14,105,43,30,27,22,70,17,68,68,85,92,79,31,62,120,57,1,79,24,2,68,72,82,70,5,77,24,10,68,14,82,82,68,10,77,27,85,15,19,29,85,13,77,13,90,9,72,70,5,77,24,10,68,78,73,61,110,92,86,98,110,71,23,93,20,77,12,27,1,19,78,69,10,82,4,8,10,86,22,16,13,79,25,79,6,13,127,58,23,85,31,26,7,71,82,68,85,29,93,67,68,81,76,16,31,44,103,102,1,93,7,93,68,90,77,25,5,95,7,85,68,28,77,95,68,78,73,61,110,92,86,98,110,71,23,93,20,77,12,27,1,19,78,69,10,82,4,8,10,86,22,16,13,79,25,79,5,31,82,69,10,82,4,8,10,86,22,16,13,79,25,79,6,13,127,58,23,85,31,26,7,71,82,68,86,1,22,98,110,58,23,94,17,76,77,20,68,69,19,92,17,68,77,82,68,2,82,27,68,85,95,83,5,30,67,28,68,67,83,85,94,69,19,92,17,68,77,18,95,62,120,77,95,44,103,27,1,94,2,92,5,85,8,79,88,70,28,67,13,70,3,10,0,19,27,94,16,1,15,81,105,57,1,68,22,84,14,27,68,71,64,12,84,13,77,13,90,19,9,61,110,40,8,1,17,94,82,75,68,87,12,3,17,86,82,13,68,16,77,68,68,71,64,12,84,13,77,13,73,2,76,10,94,87,12,3,17,86,82,77,95,44,103,18,95,62,120,68,1,76,29,3,5,71,23,12,90,44,103,28,16,65,7,83,16,1,25,93,88,3,94,16,84,31,22,98,110,19,82,16,68,68,3,26,9,19,9,16,18,64,1,26,1,19,79,16,84,92,86,98,110,78,73,61,110,87,2,6,0,19,22,85,7,78,9,10,76,70,28,67,13,70,3,10,0,19,17,88,5,83,77,69,0,82,6,81,72,1,24,1,23,90,21,94,1,69,77,6,10,71,82,70,5,77,68,20,105,57,82,16,68,1,24,1,23,90,21,94,1,69,77,6,10,71,82,26,20,85,31,79,89,19,0,85,13,79,25,10,22,67,0,85,16,126,14,14,23,71,78,69,10,82,4,8,10,86,22,16,13,79,25,79,78,13,90,84,5,85,12,70,95,62,120,16,68,1,77,24,12,90,30,85,68,9,71,31,16,65,82,17,89,1,93,70,68,72,127,58,68,1,77,79,68,19,82,16,78,81,25,29,68,14,82,26,20,85,31,79,58,19,4,81,8,26,96,101,68,19,82,16,68,1,77,79,18,82,30,16,89,1,69,25,5,95,82,110,68,9,27,14,8,19,78,12,68,16,68,70,68,109,82,0,28,66,95,94,81,7,64,1,82,26,96,101,68,19,82,16,68,1,77,79,20,71,0,16,79,28,77,94,95,62,120,16,68,1,77,18,105,57,15,61,110,84,3,28,13,84,28,85,0,1,14,7,5,65,82,86,8,64,10,8,1,87,41,109,68,28,77,20,81,31,69,8,72,16,85,89,72,2,68,5,72,19,93,87,72,11,65,28,85,17,90,67,86,0,65,28,85,18,90,67,93,3,94,1,83,18,65,93,86,31,67,1,72,20,88,67,82,7,94,1,84,19,65,94,86,3,94,9,82,13,92,89,80,31,74,6,72,25,91,67,80,3,94,5,87,13,89,87,72,7,68,28,86,21,93,67,85,10,67,28,83,24,65,94,82,0,94,1,80,22,65,87,83,31,67,4,80,13,92,92,72,6,70,28,80,22,65,94,84,6,94,2,84,20,65,93,81,2,94,1,82,18,65,94,82,11,94,2,86,17,65,93,80,2,94,4,81,13,95,95,87,31,67,0,81,13,85,92,72,2,69,6,72,22,92,67,85,2,67,28,82,19,65,88,84,31,64,2,85,13,84,92,72,2,68,28,86,16,85,67,80,7,94,9,82,13,92,87,93,31,67,8,83,13,92,88,87,31,67,6,81,13,85,91,72,1,69,28,85,22,93,67,83,5,94,7,83,13,95,95,80,31,65,7,72,16,84,86,72,11,70,28,86,17,94,67,87,0,94,2,81,18,65,92,86,31,67,9,72,19,93,89,72,0,74,28,86,24,65,86,93,31,67,6,84,13,91,86,72,11,67,28,85,20,90,67,85,6,69,28,85,19,89,67,85,1,68,28,82,25,65,94,80,2,94,9,83,13,92,87,84,31,67,3,92,13,92,89,72,1,64,0,72,19,95,94,72,1,66,1,72,16,84,89,72,4,68,28,87,19,65,88,80,31,67,3,83,13,92,92,84,31,64,3,85,13,92,95,72,2,71,7,72,16,89,86,72,2,68,3,72,16,89,91,72,1,71,4,72,23,93,67,82,2,94,2,85,21,65,94,81,7,94,6,84,13,88,95,72,11,67,28,80,20,65,94,92,31,74,4,72,16,91,89,72,2,68,7,72,18,90,67,85,4,66,28,86,18,89,67,86,3,68,28,85,25,89,67,84,31,67,3,87,13,92,95,72,2,66,2,72,21,91,67,85,10,64,28,86,18,89,67,85,0,66,28,83,13,92,95,83,31,64,5,85,13,92,90,92,31,67,1,83,13,92,88,85,31,67,0,72,24,85,67,92,11,94,1,84,24,65,87,85,31,68,0,72,16,93,87,72,2,69,2,72,19,89,67,92,4,94,6,87,13,92,93,81,31,68,28,87,16,65,93,80,5,94,1,80,18,65,88,83,31,67,7,93,13,92,89,86,31,67,0,83,13,92,87,85,31,67,0,86,13,92,95,84,31,67,0,80,13,89,93,72,2,65,0,72,19,94,88,72,2,68,9,72,16,94,94,72,2,71,8,72,16,85,95,72,6,64,28,85,18,88,67,81,10,94,1,82,13,92,89,81,31,74,2,72,16,93,87,72,2,67,9,72,19,92,67,85,7,70,28,85,16,94,67,86,4,94,2,85,24,65,94,84,2,94,2,84,13,92,89,83,31,67,6,80,13,92,89,82,31,64,5,80,13,91,90,72,1,68,28,86,19,88,67,85,6,94,7,82,13,95,94,82,31,65,8,72,19,92,91,72,2,67,28,86,18,84,67,85,4,94,2,84,25,65,94,84,31,67,9,72,19,93,89,72,0,74,28,86,24,65,86,82,31,64,0,92,13,91,95,72,0,69,28,86,21,88,67,86,7,64,28,85,25,65,94,84,10,94,7,80,13,92,91,93,31,75,6,72,16,85,94,72,2,65,9,72,23,92,67,86,7,68,28,86,19,92,67,86,3,67,28,85,24,91,67,83,5,94,1,84,17,65,94,81,31,64,0,83,13,92,92,84,31,67,9,84,13,90,93,72,1,71,4,72,19,88,95,72,1,70,1,72,16,88,93,72,1,70,7,72,18,85,67,85,5,94,2,81,19,65,94,81,7,94,6,84,13,88,95,72,11,67,28,80,20,65,94,92,31,74,4,72,16,91,89,72,1,70,5,72,24,91,67,86,6,70,28,85,24,92,67,85,6,68,28,86,21,91,67,84,31,67,4,93,13,94,86,72,4,68,28,87,13,95,92,80,31,64,3,80,13,92,92,84,31,69,28,80,20,65,93,80,0,94,1,83,20,65,88,87,31,67,6,83,13,92,67,93,10,94,1,93,13,89,89,72,0,94,6,83,13,92,94,84,31,67,8,85,13,95,90,72,10,64,28,87,18,65,91,86,31,71,6,72,20,93,67,86,7,64,28,85,18,92,67,83,3,94,1,82,18,65,94,80,4,94,6,80,13,92,91,92,31,75,7,72,22,85,67,85,3,70,28,80,19,65,94,87,3,94,1,83,21,65,93,87,4,94,2,81,19,65,93,84,11,94,2,80,16,65,86,93,31,67,3,81,13,94,87,72,2,68,28,86,21,92,67,85,2,94,6,84,13,88,95,72,4,66,28,85,20,85,67,85,11,94,8,80,13,92,90,93,31,65,2,72,24,91,67,86,6,70,28,86,21,89,67,86,1,69,28,86,21,91,67,84,31,69,2,72,19,94,93,72,3,94,7,82,13,95,95,82,31,70,1,72,19,93,89,72,11,70,28,86,17,91,67,86,1,94,2,81,17,65,94,84,31,67,9,72,19,93,89,72,0,74,28,86,24,65,86,82,31,64,0,92,13,91,95,72,0,69,28,86,21,88,67,86,7,64,28,85,25,65,94,84,10,94,7,80,13,92,91,93,31,75,6,72,16,85,94,72,2,65,9,72,23,92,67,86,7,68,28,86,19,92,67,86,3,67,28,85,24,91,67,83,5,94,1,84,17,65,94,81,31,64,0,83,13,92,92,84,31,67,7,80,13,85,90,72,2,75,5,72,16,84,91,72,1,64,9,72,16,89,87,72,1,67,8,72,16,95,67,85,5,94,2,81,19,65,94,81,7,94,6,84,13,88,95,72,11,67,28,80,20,65,94,92,31,74,4,72,16,91,89,72,1,70,5,72,24,91,67,86,6,70,28,85,24,92,67,85,6,68,28,86,21,91,67,84,31,67,4,93,13,94,86,72,4,68,28,87,13,95,92,80,31,64,3,80,13,92,92,84,31,69,28,85,17,90,67,85,11,75,28,86,17,85,67,85,3,94,1,83,21,65,94,85,31,74,9,72,24,89,67,87,7,94,8,72,16,95,94,72,7,65,28,85,23,92,67,86,6,94,1,84,24,65,91,87,31,68,3,72,20,91,67,87,10,94,2,87,17,65,93,84,7,94,3,82,13,95,93,84,31,64,2,85,13,95,95,72,2,71,2,72,22,91,67,85,3,66,28,85,17,89,67,80,1,94,1,87,17,65,94,83,7,94,2,87,22,65,93,81,1,94,2,84,25,65,93,80,2,94,9,93,13,92,92,81,31,65,8,72,16,91,67,86,7,67,28,85,16,65,89,84,31,71,0,72,22,93,67,85,6,74,28,85,25,65,87,80,31,67,5,93,13,94,93,72,10,68,28,86,20,89,67,85,11,65,28,85,22,95,67,85,4,74,28,82,24,65,89,92,31,67,3,93,13,92,95,86,31,65,28,85,21,92,67,85,3,70,28,85,18,93,67,83,31,67,9,80,13,88,86,72,1,66,8,72,16,93,67,85,10,94,2,84,23,65,92,92,31,64,9,72,24,91,67,86,3,74,28,82,17,65,92,83,31,64,4,81,13,95,91,86,31,67,8,72,16,93,86,72,4,70,28,85,21,84,67,93,5,94,1,92,16,65,94,87,10,94,6,85,13,95,91,82,31,64,2,85,13,92,92,92,31,67,3,93,13,95,67,81,6,94,9,85,13,92,90,82,31,67,4,86,13,92,92,85,31,67,1,84,13,95,94,85,31,64,0,92,13,95,91,85,31,67,5,86,13,95,91,83,31,65,8,72,16,91,67,86,6,64,28,85,20,89,67,82,3,94,5,84,13,85,94,72,7,71,28,85,25,65,87,80,31,67,6,82,13,95,91,81,31,75,6,72,19,88,91,72,2,75,1,72,16,88,89,72,1,70,6,72,17,65,94,80,10,94,3,93,13,90,89,72,0,94,2,87,21,65,93,87,7,94,2,84,21,65,88,84,31,65,8,72,19,89,87,72,2,65,1,72,23,65,94,93,4,94,1,85,16,65,92,92,31,64,9,72,16,93,86,72,4,68,28,82,17,65,92,83,31,64,2,82,13,85,89,72,2,74,28,85,17,84,67,85,2,71,28,85,19,92,67,93,5,94,1,92,16,65,94,93,1,94,9,72,19,89,89,72,1,64,1,72,19,93,67,85,6,64,28,83,23,65,94,84,3,94,1,84,21,65,91,86,31,67,3,84,13,92,88,80,31,64,3,83,13,95,90,86,31,64,0,92,13,92,89,81,31,71,4,72,19,92,90,72,2,66,6,72,25,88,67,86,7,75,28,85,16,95,67,82,1,94,1,84,17,65,89,83,31,64,1,92,13,92,89,72,11,70,28,86,16,90,67,85,2,67,28,81,17,65,93,81,7,94,1,92,24,65,93,86,4,94,1,93,16,65,88,92,31,69,2,72,19,89,91,72,2,65,28,83,22,65,93,84,1,94,4,81,13,92,92,92,31,69,3,72,16,89,93,72,2,67,6,72,16,89,88,72,4,71,28,93,20,65,94,81,4,94,4,83,13,84,89,72,2,66,5,72,19,95,95,72,2,69,28,85,20,65,93,80,6,94,2,80,19,65,94,92,31,67,0,93,13,90,91,72,2,70,9,72,24,91,67,85,11,67,28,85,18,84,67,82,2,94,2,80,23,65,93,86,2,94,2,84,16,65,94,93,5,94,7,82,13,92,95,84,31,67,5,72,19,93,88,72,2,65,0,72,16,90,91,72,5,74,28,86,16,92,67,86,3,74,28,86,21,92,67,85,6,64,28,86,21,90,67,87,11,94,1,82,13,95,90,86,31,64,2,84,13,92,94,80,31,69,7,72,16,85,67,93,11,94,8,82,13,92,88,72,2,68,8,72,16,85,93,72,7,69,28,85,19,84,67,86,7,75,28,86,16,94,67,85,11,68,28,82,24,65,93,85,10,94,1,84,19,65,94,72,4,66,28,86,18,93,67,85,10,75,28,85,23,85,67,83,31,67,0,83,13,92,87,93,31,64,0,92,13,92,95,72,1,65,2,72,23,84,67,87,11,94,2,93,13,92,95,93,31,69,6,72,23,93,67,87,4,94,2,86,23,65,87,82,31,67,8,72,16,93,86,72,2,67,5,72,16,95,94,72,10,68,28,85,25,92,67,85,10,64,28,93,13,95,91,82,31,64,2,85,13,95,95,72,2,71,2,72,22,91,67,85,3,66,28,80,23,65,94,84,3,94,2,81,18,65,93,87,4,94,1,82,19,65,94,92,7,94,1,80,24,65,93,81,6,94,3,86,13,95,95,84,31,74,9,72,24,89,67,85,4,68,28,83,17,65,94,86,2,94,6,86,13,92,95,83,31,67,8,84,13,92,87,72,11,70,28,85,20,84,67,87,1,94,9,82,13,95,90,80,31,64,4,80,13,95,93,83,31,64,4,82,13,93,67,83,1,94,1,82,23,65,88,82,31,65,28,85,21,92,67,85,3,70,28,85,18,93,67,83,31,67,9,80,13,88,86,72,1,66,8,72,16,93,67,85,10,94,2,84,23,65,92,92,31,64,9,72,24,91,67,86,3,74,28,82,17,65,86,93,31,67,8,83,13,92,91,85,31,74,1,72,18,89,67,85,7,94,2,84,25,65,94,85,3,94,2,80,23,65,94,93,5,94,6,82,13,92,88,82,31,67,4,92,13,92,90,81,31,67,5,85,13,95,91,72,7,66,28,83,17,65,94,86,10,94,1,93,24,65,93,86,7,94,1,85,13,95,93,87,31,64,5,87,13,95,94,93,31,67,5,86,13,95,91,83,31,65,8,72,16,91,67,86,6,64,28,85,20,89,67,82,3,94,5,84,13,85,94,72,7,71,28,85,25,65,87,80,31,67,6,82,13,95,91,81,31,75,6,72,19,88,91,72,2,75,1,72,16,88,89,72,1,70,6,72,17,65,94,80,10,94,3,93,13,90,89,72,0,94,2,87,21,65,93,87,7,94,1,87,17,65,88,72,2,66,7,72,19,88,94,72,2,71,8,72,16,92,88,72,2,69,1,72,16,93,67,93,11,94,8,92,13,84,86,72,2,71,28,85,16,88,67,93,3,94,1,83,21,65,93,80,31,75,3,72,20,90,67,81,3,94,5,93,13,92,95,92,31,67,5,86,13,95,92,80,31,75,28,86,21,91,67,86,1,67,28,86,17,65,94,81,1,94,7,82,13,92,95,84,31,67,0,80,13,89,93,72,2,65,0,72,16,90,91,72,1,65,7,72,19,88,93,72,1,66,8,72,19,89,94,72,10,75,28,85,18,88,67,87,11,94,1,82,13,95,91,85,31,67,1,72,23,93,67,81,3,94,7,84,13,92,90,92,31,67,8,72,25,89,67,85,6,75,28,87,19,65,92,92,31,67,7,82,13,92,92,93,31,67,6,84,13,92,87,81,31,68,8,72,16,94,67,85,5,74,28,85,20,65,88,82,31,64,4,86,13,89,89,72,1,66,8,72,23,91,67,85,0,71,28,85,17,84,67,85,7,71,28,92,25,65,89,80,31,67,9,80,13,92,94,72,6,71,28,93,23,65,93,84,11,94,6,84,13,94,88,72,1,70,5,72,19,89,93,72,2,74,28,85,17,84,67,83,7,94,1,80,24,65,86,82,31,67,8,85,13,92,92,93,31,68,1,72,19,89,89,72,1,64,1,72,19,93,94,72,2,75,6,72,22,91,67,85,3,66,28,85,20,65,93,84,4,94,1,87,17,65,94,83,7,94,6,92,13,95,94,85,31,64,0,92,13,95,91,85,31,67,5,86,13,92,88,83,31,67,0,80,13,92,94,85,31,67,9,85,13,95,94,87,31,67,2,84,13,92,94,93,31,75,5,72,16,92,95,72,10,65,28,80,18,65,93,86,10,94,1,83,23,65,91,80,31,67,7,92,13,95,92,87,31,64,2,85,13,92,89,80,31,74,3,72,16,88,89,72,2,66,28,85,17,95,67,87,31,64,3,80,13,95,92,80,31,67,3,84,13,90,87,72,0,69,28,86,21,94,67,85,7,75,28,92,25,65,93,87,3,94,5,92,13,85,86,72,10,70,28,87,21,65,87,72,2,64,1,72,24,93,67,85,6,69,28,92,23,65,94,81,31,67,0,93,13,89,87,72,5,67,28,87,16,65,93,81,2,94,1,87,18,65,86,80,31,64,1,93,13,95,91,83,31,64,0,72,16,88,93,72,4,68,28,85,17,93,67,81,11,94,1,85,16,65,93,85,7,94,2,81,16,65,94,93,2,94,1,83,25,65,93,84,11,94,1,92,21,65,91,81,31,64,0,85,13,84,86,72,5,68,28,86,19,93,67,87,0,94,1,83,13,95,91,72,3,94,1,80,18,65,94,92,31,69,3,72,16,88,86,72,2,66,0,72,18,90,67,85,11,70,28,85,25,84,67,85,4,65,28,85,22,84,67,85,1,69,28,85,21,65,93,80,0,94,2,72,23,89,67,85,0,65,28,85,19,95,67,85,7,64,28,86,16,65,93,84,5,94,1,86,16,65,93,85,6,94,8,82,13,92,94,85,31,67,5,84,13,88,91,72,2,65,28,82,17,65,94,83,1,94,1,84,17,65,90,87,31,64,2,92,13,92,87,81,31,67,1,84,13,88,92,72,10,66,28,85,18,88,67,85,10,94,2,84,16,65,93,85,2,94,4,81,13,95,92,84,31,64,1,92,13,92,86,83,31,67,9,82,13,91,87,72,2,66,28,82,21,65,94,86,10,94,1,93,24,65,94,82,1,94,7,83,13,95,93,87,31,64,0,92,13,95,91,93,31,67,4,81,13,95,90,80,31,67,1,72,20,85,67,85,11,68,28,85,18,91,67,82,3,94,4,83,13,85,94,72,2,66,5,72,25,90,67,85,11,94,2,87,24,65,94,92,4,94,3,83,13,92,93,93,31,64,4,93,13,95,95,85,31,67,8,80,13,91,88,72,2,71,7,72,20,89,67,82,7,94,1,92,13,95,92,84,31,67,6,92,13,92,92,87,31,74,3,72,19,94,67,86,1,75,28,85,24,95,67,86,5,94,1,92,17,65,90,83,31,67,2,82,13,92,92,72,2,64,5,72,21,85,67,85,3,66,28,82,16,65,93,80,2,94,4,86,13,90,91,72,2,64,5,72,24,85,67,85,3,94,2,92,13,95,92,83,31,64,0,92,13,95,90,72,1,70,1,72,19,93,86,72,1,66,28,85,21,89,67,87,7,94,4,87,13,94,87,72,2,67,1,72,16,89,93,72,2,68,7,72,19,95,90,72,1,71,2,72,19,92,89,72,1,70,6,72,21,89,67,86,2,65,28,93,25,65,93,87,31,64,5,87,13,95,67,81,0,94,3,85,13,92,95,92,31,64,1,82,13,92,67,92,7,94,1,87,17,65,92,86,31,65,6,72,16,85,88,72,2,69,8,72,16,90,95,72,2,74,4,72,23,84,67,81,6,94,2,86,21,65,93,81,31,69,7,72,19,93,89,72,10,68,28,85,21,91,67,85,2,94,2,85,17,65,90,81,31,67,4,82,13,92,92,72,4,67,28,85,22,85,67,85,1,68,28,85,18,65,94,85,1,94,1,80,25,65,89,80,31,67,2,81,13,95,93,93,31,64,2,83,13,92,94,84,31,71,3,72,25,95,67,85,0,70,28,86,25,65,93,87,4,94,1,81,20,65,91,80,31,67,3,87,13,92,89,85,31,67,4,81,13,95,94,86,31,75,2,72,24,84,67,87,31,64,0,83,13,92,92,92,31,67,9,86,13,92,94,72,2,71,7,72,16,89,86,72,1,71,3,72,16,88,93,72,1,70,7,72,18,94,67,85,2,75,28,85,25,92,67,86,3,70,28,85,19,92,67,81,3,94,2,92,13,92,95,80,31,67,8,72,16,85,67,86,0,70,28,85,25,93,67,87,10,94,2,86,25,65,94,93,2,94,1,81,20,65,93,81,6,94,1,86,13,92,91,93,31,70,7,72,22,88,67,83,7,94,1,82,21,65,94,92,5,94,2,85,20,65,87,87,31,67,0,92,13,92,88,83,31,64,1,83,13,94,67,85,10,69,28,85,16,92,67,93,5,94,9,72,16,93,86,72,11,67,28,82,17,65,86,83,31,67,6,83,13,92,89,72,10,67,28,87,20,65,90,80,31,68,28,87,25,65,93,86,7,94,1,80,19,65,88,80,31,64,5,80,13,95,95,80,31,64,4,72,16,88,93,72,10,71,28,85,17,89,67,85,3,70,28,85,17,89,67,85,0,65,28,86,18,89,67,85,7,71,28,85,23,89,67,85,10,64,28,86,19,89,67,87,10,94,2,81,16,65,94,86,5,94,0,72,19,95,88,72,4,75,28,82,21,65,94,84,5,94,8,82,13,92,91,85,31,74,6,72,21,93,67,85,10,75,28,80,25,65,94,85,5,94,1,92,23,65,94,87,5,94,1,92,22,65,93,87,3,94,2,85,13,92,93,72,1,67,8,72,19,93,67,85,10,94,1,81,23,65,91,80,31,64,5,80,13,84,90,72,1,67,0,72,21,88,67,85,7,74,28,85,16,85,67,83,6,94,2,86,19,65,91,93,31,74,9,72,19,85,67,85,0,68,28,80,21,65,89,85,31,67,7,83,13,92,91,86,31,69,0,72,21,92,67,81,7,94,2,84,20,65,94,85,1,94,1,82,23,65,93,84,4,94,6,81,13,92,87,80,31,67,5,87,13,92,87,85,31,67,5,82,13,84,93,72,0,74,28,83,20,65,94,83,10,94,2,85,25,65,94,93,3,94,7,72,16,88,94,72,2,69,2,72,16,91,92,72,1,64,0,72,16,94,86,72,2,64,6,72,17,65,93,86,11,94,2,86,19,65,89,80,31,67,0,82,13,91,90,72,2,67,0,72,25,91,67,80,3,94,2,81,21,65,93,86,10,94,3,83,13,92,87,82,31,67,9,81,13,92,86,82,31,64,3,84,13,91,88,72,1,66,9,72,24,92,67,86,3,94,1,93,13,92,88,86,31,67,7,80,13,95,90,80,31,75,5,72,16,95,92,72,1,70,8,72,16,89,87,72,2,67,8,72,16,90,89,72,11,70,28,81,21,65,87,93,31,67,7,72,19,93,67,80,6,94,5,86,13,92,89,82,31,70,2,72,22,93,67,80,2,94,1,81,13,94,92,72,2,67,3,72,16,91,88,72,2,65,2,72,16,92,88,72,2,69,4,72,19,93,90,72,4,94,2,86,17,65,91,92,31,68,0,72,16,95,94,72,6,74,28,85,24,85,67,86,2,66,28,85,25,92,67,86,0,68,28,85,24,88,67,85,11,67,28,87,16,65,93,86,0,94,5,80,13,85,90,72,2,74,1,72,16,92,86,72,2,66,0,72,18,88,67,92,6,94,2,85,25,65,94,85,3,94,1,86,13,92,91,87,31,75,8,72,18,91,67,85,0,66,28,85,25,91,67,85,5,69,28,85,18,85,67,92,11,94,8,93,13,92,88,92,31,74,28,85,19,90,67,86,2,65,28,85,19,93,67,85,6,70,28,82,22,65,94,93,3,94,9,93,13,92,86,87,31,64,5,72,25,90,67,85,4,74,28,85,19,91,67,85,0,94,1,85,18,65,94,80,11,94,6,80,13,92,93,81,31,64,2,93,13,95,93,83,31,74,6,72,16,90,67,80,31,64,0,93,13,95,87,72,1,64,5,72,19,93,88,72,5,71,28,85,22,89,67,86,3,71,28,86,16,91,67,85,1,74,28,80,25,65,89,84,31,65,0,72,19,95,94,72,2,75,8,72,19,92,95,72,1,74,28,85,24,88,67,85,7,68,28,85,25,92,67,86,1,74,28,85,22,88,67,81,6,94,0,72,16,85,91,72,1,65,0,72,16,93,95,72,0,70,28,86,18,65,94,84,6,94,1,85,17,65,94,86,31,67,8,87,13,95,93,81,31,65,6,72,16,94,95,72,1,65,1,72,16,89,95,72,1,64,9,72,23,85,67,86,0,65,28,85,19,90,67,93,1,94,6,81,13,92,88,80,31,67,5,84,13,95,94,92,31,64,2,72,16,95,89,72,1,70,9,72,16,90,93,72,11,64,28,86,21,84,67,92,0,94,9,83,13,92,93,72,7,74,28,80,25,65,94,84,3,94,5,87,13,95,91,87,31,64,28,85,16,93,67,81,0,94,9,93,13,92,95,81,31,68,0,72,19,93,94,72,2,71,2,72,19,88,67,86,0,66,28,85,23,92,67,83,5,94,1,86,25,65,86,81,31,64,4,72,21,85,67,81,11,94,1,80,22,65,93,81,3,94,1,80,20,65,94,82,7,94,1,93,19,65,93,86,6,94,6,87,13,95,90,85,31,67,2,82,13,93,67,86,1,70,28,85,16,84,67,85,3,66,28,80,19,65,87,81,31,64,2,82,13,90,91,72,5,74,28,85,21,95,67,85,3,69,28,86,25,65,94,82,5,94,2,86,25,65,93,80,3,94,1,82,21,65,94,86,7,94,1,82,13,92,86,84,31,75,4,72,25,90,67,86,7,67,28,80,25,65,94,80,5,94,2,86,13,92,92,80,31,69,1,72,16,94,89,72,1,69,28,80,13,92,88,92,31,67,2,82,13,88,67,85,2,71,28,85,22,95,67,85,3,66,28,81,18,65,93,86,11,94,1,80,19,65,88,80,31,67,2,81,13,84,94,72,1,65,3,72,20,91,67,85,5,71,28,85,20,88,67,85,1,67,28,85,18,85,67,85,0,65,28,86,16,91,67,86,1,66,28,82,18,65,93,80,31,74,7,72,19,95,92,72,2,70,6,72,19,88,95,72,6,68,28,85,18,84,67,85,10,64,28,86,19,90,67,85,10,68,28,85,18,84,67,85,1,68,28,84,13,95,92,82,31,67,9,92,13,91,91,72,2,66,6,72,23,88,67,82,3,94,1,85,17,65,94,86,31,67,9,84,13,95,92,84,31,64,8,72,16,91,89,72,2,69,5,72,16,89,93,72,2,70,6,72,16,95,91,72,1,66,5,72,20,88,67,93,1,94,1,86,23,65,93,87,11,94,1,92,18,65,93,81,7,94,9,81,13,92,93,87,31,67,7,81,13,92,92,86,31,67,1,92,13,92,88,82,31,74,5,72,20,94,67,82,6,94,1,83,13,95,95,72,7,70,28,81,20,65,94,82,5,94,4,86,13,90,91,72,2,64,4,72,16,93,89,72,6,94,5,82,13,92,89,80,31,64,1,83,13,92,94,83,31,67,7,80,13,95,95,81,31,70,28,86,17,89,67,80,11,94,6,84,13,92,93,84,31,68,2,72,19,95,93,72,1,67,0,72,16,85,94,72,1,65,6,72,16,84,91,72,2,74,1,72,18,92,67,86,1,65,28,81,20,65,87,85,31,67,4,85,13,85,92,72,7,71,28,80,18,65,90,92,31,67,9,92,13,95,67,82,11,94,2,86,22,65,94,86,3,94,1,86,17,65,93,87,4,94,1,87,23,65,94,92,4,94,2,87,17,65,94,83,31,71,2,72,19,88,91,72,11,70,28,85,23,65,93,80,2,94,4,92,13,92,91,82,31,64,1,72,16,94,91,72,4,67,28,85,18,91,67,86,4,94,1,85,13,92,92,87,31,75,0,72,23,84,67,85,2,64,28,85,24,89,67,85,2,66,28,92,24,65,94,83,0,94,2,87,21,65,87,85,31,67,7,72,16,85,67,85,0,65,28,85,16,94,67,86,3,67,28,86,16,92,67,80,6,94,2,87,17,65,94,81,0,94,1,92,16,65,94,81,5,94,9,87,13,92,93,80,31,67,2,80,13,92,88,93,31,64,1,92,13,92,86,84,31,74,4,72,16,94,95,72,2,69,2,72,16,91,86,72,2,64,8,72,16,85,95,72,10,74,28,85,17,85,67,85,5,70,28,85,18,84,67,85,1,68,28,82,20,65,91,81,31,67,1,83,13,95,67,82,11,94,1,82,16,65,93,80,10,94,7,83,13,95,94,86,31,67,9,85,13,92,90,82,31,64,4,82,13,93,67,85,7,75,28,87,24,65,88,82,31,65,28,86,18,89,67,86,0,70,28,85,18,93,67,83,31,67,0,83,13,92,87,93,31,64,0,92,13,92,95,72,1,65,2,72,22,90,67,83,1,94,8,86,13,94,90,72,10,94,4,92,13,94,88,72,1,71,1,72,22,84,67,87,3,94,1,84,24,65,86,92,31,67,0,83,13,92,94,87,31,67,8,81,13,92,86,86,31,67,6,72,19,94,87,72,1,66,9,72,19,93,67,85,0,69,28,93,18,65,94,85,1,94,1,84,17,65,91,86,31,67,4,83,13,92,86,84,31,64,4,92,13,95,91,84,31,64,0,92,13,95,93,80,31,67,1,80,13,92,91,82,31,70,2,72,16,91,67,86,1,70,28,86,20,65,91,83,31,68,2,72,22,93,67,85,0,75,28,84,13,85,87,72,2,71,9,72,20,90,67,85,2,75,28,86,21,95,67,86,7,70,28,86,21,95,67,86,0,66,28,85,23,65,89,92,31,67,6,82,13,85,86,72,2,74,28,85,19,84,67,85,3,70,28,85,21,90,67,86,0,94,2,85,16,65,90,81,31,64,0,92,13,94,94,72,5,94,1,93,21,65,92,92,31,74,28,85,16,84,67,86,1,66,28,82,17,65,91,92,31,64,3,84,13,95,90,80,31,67,8,72,16,95,95,72,10,70,28,85,20,94,67,93,5,94,1,82,16,65,94,80,4,94,4,93,13,95,91,82,31,64,0,85,13,95,95,92,31,64,0,84,13,90,89,72,2,67,3,72,18,92,67,85,10,71,28,85,18,93,67,85,11,69,28,92,19,65,93,86,0,94,2,84,25,65,93,86,7,94,1,87,23,65,93,86,10,94,4,86,13,92,89,72,1,65,7,72,16,94,89,72,7,67,28,82,19,65,87,85,31,70,2,72,16,95,89,72,2,69,28,86,18,95,67,85,4,74,28,81,19,65,94,92,1,94,1,93,16,65,93,84,10,94,1,93,16,65,87,87,31,64,1,82,13,92,95,86,31,64,4,72,23,89,67,85,5,64,28,86,18,88,67,85,0,65,28,85,16,65,94,84,4,94,2,85,24,65,94,80,6,94,7,84,13,92,87,83,31,66,28,80,19,65,93,93,31,67,2,80,13,91,91,72,5,66,28,81,18,65,93,87,11,94,8,82,13,92,95,86,31,68,3,72,18,85,67,82,3,94,1,84,20,65,94,92,6,94,2,87,22,65,92,81,31,64,4,82,13,95,93,85,31,64,0,72,16,88,93,72,4,68,28,85,17,93,67,85,3,70,28,80,19,65,94,87,3,94,1,83,21,65,93,87,4,94,2,81,19,65,93,84,11,94,2,80,16,65,86,93,31,67,3,81,13,94,87,72,1,70,28,86,21,91,67,83,2,94,1,86,16,65,94,86,7,94,6,81,13,92,91,82,31,67,8,72,25,94,67,86,3,69,28,85,16,89,67,80,2,94,1,83,23,65,94,82,3,94,2,86,25,65,93,81,3,94,0,72,22,84,67,86,6,64,28,81,13,85,92,72,2,65,8,72,16,93,95,72,2,65,0,72,17,65,94,87,1,94,4,86,13,95,94,81,31,68,28,85,24,65,93,84,2,94,9,82,13,92,90,72,2,66,3,72,19,92,88,72,6,65,28,92,13,95,93,87,31,67,8,84,13,90,67,85,3,75,28,92,22,65,94,80,10,94,3,82,13,95,91,84,31,64,0,81,13,92,94,82,31,67,8,80,13,92,90,86,31,67,8,86,13,92,92,84,31,64,5,72,21,95,67,83,5,94,1,93,24,65,94,80,5,94,1,82,19,65,89,92,31,67,9,80,13,95,93,84,31,67,7,93,13,92,90,93,31,67,6,87,13,84,95,72,4,64,28,86,18,91,67,85,0,74,28,82,21,65,94,84,5,94,7,87,13,91,93,72,2,67,0,72,16,95,67,85,11,64,28,86,19,84,67,82,2,94,1,87,17,65,93,87,2,94,1,80,17,65,93,87,3,94,8,80,13,95,92,87,31,67,2,83,13,84,93,72,2,74,28,85,25,95,67,85,6,66,28,86,16,85,67,86,0,94,1,86,18,65,94,93,0,94,1,87,23,65,94,92,31,64,5,85,13,88,88,72,2,64,6,72,16,94,67,85,1,70,28,92,13,91,91,72,2,64,5,72,19,89,93,72,4,67,28,92,24,65,94,83,31,70,3,72,16,93,90,72,2,64,0,72,19,94,94,72,2,74,8,72,25,92,67,86,0,67,28,85,20,85,67,82,7,94,2,86,25,65,93,84,31,67,1,82,13,92,93,86,31,67,1,84,13,95,90,80,31,64,4,82,13,95,90,87,31,64,3,92,13,92,88,86,31,67,6,93,13,92,93,87,31,67,4,92,13,84,95,72,4,64,28,86,19,88,67,86,5,94,6,80,13,92,95,82,31,74,6,72,16,89,92,72,2,67,0,72,16,95,67,85,7,65,28,80,25,65,91,82,31,67,3,84,13,92,88,86,31,64,4,87,13,95,92,92,31,74,4,72,20,95,67,86,6,70,28,93,19,65,94,83,31,64,0,85,13,95,95,72,1,67,8,72,19,94,67,86,3,75,28,83,16,65,94,87,5,94,1,92,13,93,67,85,4,74,28,85,19,91,67,85,0,94,1,85,18,65,94,83,1,94,1,84,17,65,90,87,31,64,2,92,13,92,91,86,31,69,4,72,16,95,90,72,10,66,28,86,17,84,67,86,11,94,2,87,22,65,94,81,6,94,4,81,13,92,92,87,31,67,6,85,13,92,91,81,31,64,1,86,13,84,93,72,10,75,28,87,13,92,86,93,31,64,3,82,13,95,93,81,31,67,0,72,16,88,95,72,1,64,0,72,19,89,94,72,1,71,4,72,16,85,93,72,2,66,6,72,23,90,67,85,11,71,28,85,20,93,67,82,3,94,5,87,13,91,92,72,10,74,28,82,23,65,94,83,31,67,6,83,13,95,91,86,31,67,0,92,13,95,90,80,31,67,8,80,13,95,93,93,31,67,7,93,13,85,95,72,2,70,8,72,18,95,67,82,10,94,1,81,13,95,92,80,31,64,2,82,13,92,92,87,31,68,5,72,16,95,95,72,2,74,6,72,19,95,95,72,2,66,28,86,18,84,67,87,31,71,0,72,19,91,67,93,4,94,7,82,13,88,86,72,2,67,7,72,16,90,89,72,0,67,28,93,19,65,90,83,31,67,1,82,13,92,94,86,31,67,0,81,13,92,90,86,31,64,3,80,13,90,86,72,1,64,7,72,19,92,92,72,1,75,28,85,25,92,67,85,3,64,28,83,18,65,89,82,31,70,2,72,16,94,95,72,2,69,4,72,19,94,88,72,1,64,0,72,19,89,95,72,1,66,9,72,23,90,67,85,5,69,28,84,13,93,67,84,31,66,77,95,44,103,6,10,71,82,93,5,72,3,71,77,72,127,58,68,1,77,79,0,86,17,95,0,68,69,9,8,82,21,87,1,69,65,79,16,1,78,0,28,66,12,12,5,3,66,0,84,13,77,27,86,15,70,4,80,13,77,27,85,15,6,2,88,16,93,95,72,19,6,1,88,21,65,92,90,9,72,70,5,77,24,10,90,9,72,70,5,77,24,10,72,19,6,2,88,21,89,67,68,71,67,12,85,16,65,92,90,9,72,70,5,77,24,10,90,9,72,70,5,77,24,10,90,9,72,70,5,77,24,10,90,9,72,70,5,77,24,10,90,9,72,70,5,77,24,10,77,8,127,58,68,1,77,79,23,71,22,10,94,66,2,26,16,19,78,12,68,71,1,14,3,84,23,84,68,29,81,28,16,87,72,10,1,79,9,3,95,62,120,77,100,33,0,0,0,0,0,0,0,0};

int main(){

    char *key = getenv("XKEY");
    if((!key) ||strncmp("mod3r0d!",key,8 )){
        puts(";[");
        return 1;
    }
    unsigned long long val = *(unsigned long long *)key;
    unsigned long long *ptr = (unsigned long long *)flagged;
    while (*ptr != 0) {
        *ptr = *ptr ^ val;
        ptr += 1;
    }
    puts(flagged);
}