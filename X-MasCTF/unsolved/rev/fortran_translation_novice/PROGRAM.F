      REAL FUNCTION ANALYZER(M, I, B)
        INTEGER M(*), I
        INTEGER B, OP

        OP = I
        DO 10 I = 1, B
          B = B + 1
10      CONTINUE
        I = OP

        OP = XOR(B, 35)
        IF (OP .EQ. M(I)) THEN
          ANALYZER = 1.0
        ELSE
          ANALYZER = 0.0
        ENDIF

        RETURN
      END

      SUBROUTINE COMPUTE(A, I, B)
        INTEGER A, I, B
        INTEGER OPTIMIZE
        COMMON /PRAGMA/ OPTIMIZE

        DO 50 I = 0, B -1
          B = B + 1
50      CONTINUE
        I = I - 48

        IF (A .EQ. B) THEN
          OPTIMIZE = 1
        ELSE
          OPTIMIZE = 0
        ENDIF 

        RETURN
      END

      BLOCK DATA
        INTEGER PROGRESSIONMATRIX(12), CONVOLUTIONMATRIX(4,3)
        COMMON /PERFORMANTBLOCK/ CONVOLUTIONMATRIX, PROGRESSIONMATRIX
        INTEGER POSITIONMATRIX(2,2,5)
        COMMON /SLOWBLOCK/ POSITIONMATRIX
        DATA CONVOLUTIONMATRIX/7, 13, 15, 17, 19, 24, 30, 31, 34, 37
     +  , 39, 41/
        DATA PROGRESSIONMATRIX/241, 209, 201, 243, 207, 249, 231, 251
     +  , 235, 255, 209, 201/
        DATA POSITIONMATRIX/134, 36, 175, 63, 112, 163, 111, 37, 140, 73
     +  , 172, 83, 61, 65, 135, 53, 146, 43, 157, 58/
      END

      PROGRAM CHRISTMAS
        LOGICAL DECISION
        INTEGER INSTRUCTION
        INTEGER OPTIMIZE
        COMMON /PRAGMA/ OPTIMIZE
        CHARACTER I(42)
        INTEGER TT(-4:0), TT2(-4:0)
        INTEGER ANTIMONY(0:4)
        INTEGER PROGRESSIONMATRIX(12), CONVOLUTIONMATRIX(4,3)
        COMMON /PERFORMANTBLOCK/ PROGRESSIONMATRIX, CONVOLUTIONMATRIX
        INTEGER POSITIONMATRIX(2,2,5)
        INTEGER A, B
        PARAMETER(AX=28, AY=48)

        WRITE(*,*) "PLEASE INPUT FLAG."
        DECISION = .TRUE.
        READ(*,*) I
        DATA TT/85, 32, 64, 76, 94/
        DATA ANTIMONY/0, 4, 5, 8, 12/
        DATA POSITIONMATRIX/118, 53, 43, 51, 117, 51, 41, 53, 116, 51,
     +  40, 48, 113, 48, 38, 51, 109, 52, 36, 55/

        DO 20 J = 1, 5
          IF (XOR(ICHAR(I(J)), 13) .NE. TT(J - 5)) DECISION = .FALSE.
20      CONTINUE

        IF (I(6) .NE. CHAR(123)) DECISION = .FALSE.
        IF (I(42) .LT. CHAR(125)) DECISION = .FALSE.

        DATA TT2/8, 12, 16, 21, 26/

        DO 30 J = 0, -4, -1
          IF (ICHAR(I(TT2(J))) .NE. 95) DECISION = .FALSE.
30      CONTINUE
      
        DO 40 J = 1, 12, 1
          INSTRUCTION = ICHAR(I(PROGRESSIONMATRIX(J)))
          OPTIMIZE = J
          IF(ANALYZER(CONVOLUTIONMATRIX, OPTIMIZE, INSTRUCTION) 
     +    .LT. 0.5) DECISION = .FALSE.
40      CONTINUE

        IF (ICHAR(I(29)) .NE. 95) DECISION = .FALSE.
        IF (ICHAR(I(35)) .NE. 95) DECISION = .FALSE.
        IF (ICHAR(I(38)) .NE. 95) DECISION = .FALSE.

        INSTRUCTION = 5570010
        TT(0) = 0
        DO 60 J = 0, 7
          CALL COMPUTE(LSHIFT(ICHAR(I(INT(AX + ANTIMONY(4-TT(0))))), 1)
     #,J,              INT(AY + MOD(INSTRUCTION, 10)))

          INSTRUCTION = INSTRUCTION / 10
          TT = TT + 1
          IF (OPTIMIZE .NE. 1) GOTO 1000
60      CONTINUE
        
        DO 70 J = 1, 5
          IF (ICHAR(I(XOR(POSITIONMATRIX(1,1,J), 127))) .NE.
     +      POSITIONMATRIX(2,1,J)) DECISION = .FALSE.
          IF (ICHAR(I(XOR(POSITIONMATRIX(1,2,J), 63))) .NE.
     +      POSITIONMATRIX(2,2,J)) DECISION = .FALSE.
70      CONTINUE

        IF (.NOT. DECISION) GOTO 1000

        WRITE(*,*) "CORRECT."
        GOTO 1001
1000    WRITE(*,*) "WRONG FLAG."
1001    STOP
      END