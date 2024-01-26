from burp import IBurpExtender, ITab
from javax.swing import JPanel, JButton, SwingUtilities, JOptionPane
from java.awt import GridBagLayout, GridBagConstraints
import random

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        # Standard setup for a Burp extension
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Tic Tac Toe")
        
        # Initialize the UI
        self._panel = JPanel()
        self.initializeGame()
        
        # Add the custom tab
        SwingUtilities.invokeLater(self.addCustomTab)
        
    def addCustomTab(self):
        # Add this panel as a custom tab in Burp Suite
        self._callbacks.addSuiteTab(self)
        
    def getTabCaption(self):
        # Tab caption in Burp Suite
        return "Tic Tac Toe"
        
    def getUiComponent(self):
        # Return the main UI component
        return self._panel

    def initializeGame(self):
        # Use GridBagLayout for flexible component placement
        self._panel.setLayout(GridBagLayout())
        self.gameState = [['' for _ in range(3)] for _ in range(3)]
        self.currentPlayer = random.choice(["X", "O"])  # Randomly choose the starting player
        
        gbc = GridBagConstraints()
        
        # Reset button configuration
        resetButton = JButton('Reset', actionPerformed=self.resetGame)
        gbc.gridx = 1  # Center column
        gbc.gridy = 0  # Top row
        gbc.gridwidth = 1  # Occupy only one column width
        self._panel.add(resetButton, gbc)
        
        # Configure and add Tic Tac Toe grid buttons
        self.buttons = [[None for _ in range(3)] for _ in range(3)]
        for row in range(3):
            for col in range(3):
                button = JButton(actionPerformed=lambda event, row=row, col=col: self.buttonClicked(event, row, col))
                self.buttons[row][col] = button
                gbc.gridx = col
                gbc.gridy = row + 1  # Offset by 1 due to the reset button at the top
                gbc.gridwidth = 1
                self._panel.add(button, gbc)

    def buttonClicked(self, event, row, col):
        # Action for when a Tic Tac Toe button is clicked
        if not self.gameState[row][col]:
            self.gameState[row][col] = self.currentPlayer
            button = event.getSource()
            button.setText(self.currentPlayer)
            if self.checkWin():
                JOptionPane.showMessageDialog(self._panel, f"Player {self.currentPlayer} wins!")
                self.resetGame(None)
                return
            if self.checkTie():
                JOptionPane.showMessageDialog(self._panel, "It's a tie!")
                self.resetGame(None)
                return
            self.togglePlayer()
            if self.currentPlayer == "O":
                self.cpuMove()

    def checkWin(self):
        # Check for a win condition
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
        # Check for a tie condition
        for row in self.gameState:
            if '' in row:
                return False
        return True

    def cpuMove(self):
        # CPU makes a random move
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
            self.togglePlayer()

    def togglePlayer(self):
        # Toggle the current player
        self.currentPlayer = "O" if self.currentPlayer == "X" else "X"

    def resetGame(self, event):
        # Reset the game
        for row in range(3):
            for col in range(3):
                self.buttons[row][col].setText("")
                self.gameState[row][col] = ''
        self.currentPlayer = random.choice(["X", "O"])  # Randomly choose the starting player for the new game
