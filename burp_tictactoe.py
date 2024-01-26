from burp import IBurpExtender, ITab
from javax.swing import JPanel, JButton, JFrame, JLabel, SwingUtilities, JOptionPane
from java.awt import GridLayout
import random

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Tic Tac Toe")
        
        self._panel = JPanel()
        
        self.initializeGame()
        
        SwingUtilities.invokeLater(self.addCustomTab)
        
    def addCustomTab(self):
        self._callbacks.addSuiteTab(self)
        
    def getTabCaption(self):
        return "Tic Tac Toe"
        
    def getUiComponent(self):
        return self._panel

    def initializeGame(self):
        self._panel.setLayout(GridLayout(4, 3))  # Updated for an additional row for the reset button
        self.buttons = [[None for _ in range(3)] for _ in range(3)]
        self.gameState = [['' for _ in range(3)] for _ in range(3)]
        self.currentPlayer = random.choice(["X", "O"])  # Randomly choose who starts
        
        for row in range(3):
            for col in range(3):
                button = JButton(actionPerformed=lambda event, row=row, col=col: self.buttonClicked(event, row, col))
                self.buttons[row][col] = button
                self._panel.add(button)
        
        # Reset button
        resetButton = JButton('Reset', actionPerformed=self.resetGame)
        self._panel.add(resetButton)

    def buttonClicked(self, event, row, col):
        # Prevent overwriting a cell
        if not self.gameState[row][col]:
            self.gameState[row][col] = self.currentPlayer
            button = event.getSource()
            button.setText(self.currentPlayer)
            if self.checkWin():
                JOptionPane.showMessageDialog(self._panel, "Player " + self.currentPlayer + " wins!")
                self.resetGame(None)
                return
            if self.checkTie():
                JOptionPane.showMessageDialog(self._panel, "It's a tie!")
                self.resetGame(None)
                return
            self.currentPlayer = "O" if self.currentPlayer == "X" else "X"
            if self.currentPlayer == "O":
                self.cpuMove()

    def checkWin(self):
        # Check rows, columns, and diagonals for a win
        for i in range(3):
            if self.gameState[i][0] == self.gameState[i][1] == self.gameState[i][2] != '':
                return True
            if self.gameState[0][i] == self.gameState[1][i] == self.gameState[2][i] != '':
                return True
        if self.gameState[0][0] == self.gameState[1][1] == self.gameState[2][2] != '':
            return True
        if self.gameState[0][2] == self.gameState[1][1] == self.gameState[2][0] != '':
            return True
        return False

    def checkTie(self):
        for row in self.gameState:
            if '' in row:
                return False
        return True

    def cpuMove(self):
        emptyCells = [(r, c) for r in range(3) for c in range(3) if self.gameState[r][c] == '']
        if emptyCells:
            row, col = random.choice(emptyCells)
            self.gameState[row][col] = "O"
            self.buttons[row][col].setText("O")
            if self.checkWin():
                JOptionPane.showMessageDialog(self._panel, "CPU wins!")
                self.resetGame(None)
                return
            if self.checkTie():
                JOptionPane.showMessageDialog(self._panel, "It's a tie!")
                self.resetGame(None)
                return
            self.currentPlayer = "X"

    def resetGame(self, event):
        for row in range(3):
            for col in range(3):
                self.buttons[row][col].setText("")
                self.gameState[row][col] = ''
        self.currentPlayer = random.choice(["X", "O"])  # Randomly choose who starts for the new game
