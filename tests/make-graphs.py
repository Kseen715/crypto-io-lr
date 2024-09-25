import pandas as pd
import matplotlib.pyplot as plt

# Read CSV files without headers and assign column names
ecb_df = pd.read_csv('./temp/ecb.log', header=None, names=['index', 'value'])
cfb_df = pd.read_csv('./temp/cfb.log', header=None, names=['index', 'value'])
cbc_df = pd.read_csv('./temp/cbc.log', header=None, names=['index', 'value'])

# Plot the data
plt.figure(figsize=(10, 6))

plt.plot(ecb_df['index'], ecb_df['value'], label='ECB')
plt.plot(cfb_df['index'], cfb_df['value'], label='CFB')
plt.plot(cbc_df['index'], cbc_df['value'], label='CBC')

# Set y-axis to logarithmic scale
# plt.yscale('log')

# Add labels and title
plt.xlabel('Changed bit in plaintext')
plt.ylabel('Count of changed bits in ciphertext')
plt.title('Avalanche effect of different block cipher modes')

# Add legend
plt.legend()

# Display the plot
# plt.show()

# Save the plot
plt.savefig('./temp/block_cipher_modes.png')