#!/usr/bin/env python
# coding: utf-8

# # Project MAPLE
# 
# **Quantum-Proof, Location-Based Credit Transaction Authorization: Pioneering the Future of Secure Transactions**
# 
# As credit card fraud looms larger in the digital age, financial giants and consumers alike cry out for advanced, privacy-centric solutions. Enter our Quantum-Proof, Location-Based Credit Transaction Authorization System—a confluence of innovation and security.
# 
# **Concept:** Whenever a credit card transaction unfolds, our system is on guard, corroborating the authenticity of the transaction based on its originating location. It cross-references the transaction's geocoordinates with the cardholder's recent whereabouts. Importantly, this scrutiny ensues without unveiling the underlying location data.
# 
# **Technology:** Our system employs Fully Homomorphic Encryption (FHE), an encryption paradigm that allows computations on encrypted data, obviating the need for decryption. Thus, it validates the transaction location against the cardholder's without ever exposing either. This transcends conventional security levels while upholding user data sanctity. Furthermore, with quantum computing on the horizon, our quantum-resistant design stands as a bulwark against present and prospective cryptographic threats.
# 
# **Integration with POS Systems:** Seamlessly interfacing with Point-of-Sale (POS) units, our system extracts transaction geocoordinates in real-time. This ensures immediate verification against the user's known locations, making transaction approvals swift and secure.
# 
# **Value Proposition:** This system heralds a dawn of diminished credit fraud risks. Its adaptive algorithms evolve with a user's location habits, minimizing false alarms while amplifying genuine transaction approvals. The result? An augmented customer experience, bolstered trust, and optimized operational efficiencies.
# 
# In the cosmos of luxury and avant-garde tech, Amex's alliance with Prada shines brilliantly. Yet, what if this shimmer could be intensified? Our Quantum-Proof, Location-Based Authorization system envisions this zenith—marrying elite fashion with next-gen security. Visualize an Amex wearable, suffused with the allure of Prada or another luxury brand, but also fortified with our groundbreaking tech. Transactions evolve into harmonious symphonies of style and fortitude. As Amex tailors its future in haute wearable tech, we present the golden thread—a promise to safeguard against the quantum vagaries looming ahead. The ensemble is not just exquisite; it's inviolably robust.

# In[1]:


def string_to_ascii(str):
    return [ord(c) for c in str]


# <br>
# 
# ## Step 1. Import and initialize

# In[2]:


import os
import csv
import copy
import pyhelayers
import utils
print("misc. init ready")


# In[3]:


db_filename = os.path.join("data", "zones", "zones_002.csv") # input database file name
primary_zone = "77.147424,139.930624" # primary_zone to get its transaction_zone
print("input parameters ready.")


# <br>
# 
# ## Step 2. Initialize FHE parameters
# Note: Although we can hide them away, for demonstration purposes, we show you the parameters (e.g. cyclotomic polynomial) here. The parameters have been chosen to provide a somewhat faster running time with a non-realistic security level. Do not use these parameters in real applications.

# In[4]:


conf = pyhelayers.HelibConfig()
conf.p = 127 # Plaintext prime modulus
# this will give 32 slots
conf.m = 128 # Cyclotomic polynomial - defines phi(m)
conf.r = 1 # Hensel lifting
conf.L = 1000 # Number of bits of the modulus chain
conf.c = 2 # Number of columns of Key-Switching matrix
print("configruation ready")


# <br>
# 
# ## Step 3. Initialize HElib BGV Context

# In[5]:


utils.start_timer()
he = pyhelayers.HelibBgvContext()
he.init(conf)
print(he)
utils.end_timer("Initializing HE context")


# In[6]:


assert(he.get_traits().is_modular_arithmetic)
assert(he.get_traits().arithmetic_modulus >= 127)
print ("asserts passed")


# <br>
# 
# ## Step 4. Read world transaction database from file
# The code below will make sure no string is longer than he.slot_count().

# In[7]:


transaction_db = []
with open(db_filename, encoding="utf8") as db_file_csv:
    csv_reader = csv.reader(db_file_csv, delimiter=',')
    for row in csv_reader:
        ascii_primary_zone = string_to_ascii(row[0])
        ascii_transaction_zone = string_to_ascii(row[1])

        if len(row[0]) > he.slot_count():
            raise RunTimeError("primary_zone name ", row[0], " too long")
        if len(row[1]) > he.slot_count():
            raise RunTimeError("transaction_zone name ", row[1], " too long")
        transaction_db.append((ascii_primary_zone, ascii_transaction_zone))
print("finished reading database")


# <br>
# 
# ## Step 5. Encrypt the database

# In[8]:


utils.start_timer()
enc = pyhelayers.Encoder(he)
encrypted_transaction_db = []
for primary_zone_str, transaction_zone_str in transaction_db:
    primary_zone_ctxt = enc.encode_encrypt(primary_zone_str)
    transaction_zone_ctxt = enc.encode_encrypt(transaction_zone_str)
    encrypted_transaction_db.append((primary_zone_ctxt, transaction_zone_ctxt))
utils.end_timer("Encrypting DB")


# <br>
# 
# ## Step 6. Encrypt the query

# In[9]:


utils.start_timer()
primary_zone_ascii = string_to_ascii(primary_zone)
encrypted_query = enc.encode_encrypt(primary_zone_ascii)
utils.end_timer("Encrypting Query")


# <br>
# 
# ## Step 7. Perform the encrypted database search

# In[10]:


utils.start_timer()
eval = pyhelayers.NativeFunctionEvaluator(he)
mask = []

n = he.slot_count()
is_power_of_2 = (n & (n-1) == 0)

# For every entry in the database we perform the following calculation:
for primary_zone,transaction_zone in encrypted_transaction_db:
    # Copy of database key: a primary_zone name
    mask_entry = primary_zone
    # Calculate the difference.
    # In each slot now we'll have 0 when characters match,
    # or non-zero when there's a mismatch.
    mask_entry.sub(encrypted_query)

    # Fermat's little theorem:
    # Since the underlying plaintext are in modular arithmetic,
    # Raising to the power of modulusP convers all non-zero values to 1.
    eval.power_in_place(mask_entry, conf.p - 1)

    # Negate the ciphertext.
    # Now we'll have 0 for match, -1 for mismatch.
    mask_entry.negate()

    # Add 1.
    # Now we'll have 0 for match, -1 for mismatch.
    mask_entry.add_scalar(1)

    # We'll now multiply all slots together, since
    # we want a complete match across all slots
        # If slot count is a power of 2 there's an efficient way to do it:
        # we'll do a rotate-and-multiply algorithm, similar to
        # a rotate-and-sum one.
    if is_power_of_2:
        rot = 1
        while rot < he.slot_count():
            tmp = copy.deepcopy(mask_entry)
            tmp.rotate(-rot)
            mask_entry.multiply(tmp)
            rot *= 2 
    else:
        # Otherwise we'll create all possible rotations, and multiply all of
        # them.
        # Note that for non powers of 2 a rotate-and-multiply algorithm
        # can still be used as well, though it's more complicated and
        # beyond the scope of this example.
        rotated_masks = pyhelayers.CTileVector([mask_entry] * he.slot_count())
        for i in range(1, he.slot_count()):
            rotated_masks[i].rotate(-i)
        mask_entry = eval.total_product(rotated_masks, he)

    # mask_entry is now either all 1s if query==primary_zone,
    # or all 0s otherwise.
    # After we multiply by transaction_zone name it will be either
    # the transaction_zone name, or all 0s.
    mask_entry.multiply(transaction_zone)
    # We collect all our findings
    mask.append(mask_entry)

# Aggregate results into a single ciphertext
value = mask[0]
for i in range(1, len(mask)):
    value.add(mask[i])
utils.end_timer("Query search")
        
# Step 7.5: Check if transaction_zone matches primary_zone

def compare_encrypted_zones(encrypted_transaction_zone, encrypted_primary_zone):
    # Create an encrypted mask to check for equality
    mask_check = copy.deepcopy(encrypted_transaction_zone)
    mask_check.sub(encrypted_primary_zone)
    eval.power_in_place(mask_check, conf.p - 1)
    mask_check.negate()
    mask_check.add_scalar(1)
    
    # Decrypt and check the result
    ascii_check_result = enc.decrypt_decode_int(mask_check)
    
    # If any value is 0, the zones are different
    if any(val == 0 for val in ascii_check_result):
        return "Zones are different. Flagging."
    else:
        return "Payment authorized"

auth_result = compare_encrypted_zones(value, encrypted_query)
print(auth_result)

def debug_encrypted_zones(encrypted_transaction_zone, encrypted_primary_zone):
    # Step 1: Subtract
    mask_check = copy.deepcopy(encrypted_transaction_zone)
    mask_check.sub(encrypted_primary_zone)
    print("After subtraction:", enc.decrypt_decode_int(mask_check))

    # Step 2: Power
    eval.power_in_place(mask_check, conf.p - 1)
    print("After power:", enc.decrypt_decode_int(mask_check))

    # Step 3: Negate and add scalar
    mask_check.negate()
    mask_check.add_scalar(1)
    print("After negate and add:", enc.decrypt_decode_int(mask_check))
    
    # Checking
    ascii_check_result = enc.decrypt_decode_int(mask_check)
    if any(val == 0 for val in ascii_check_result):
        return "Zones are different. Flagging."
    else:
        return "Payment authorized"

auth_result = debug_encrypted_zones(value, encrypted_query)
print(auth_result)


# <br>
# 
# ## Step 8. Decrypt the result

# In[11]:


# Step 8: Decrypt the result (only if flagged)

if auth_result == "Zones are different. Flagging.":
    utils.start_timer()
    ascii_result = enc.decrypt_decode_int(value)
    utils.end_timer("Decrypting result")

    # Decrypting primary_zone
    ascii_primary_zone = enc.decrypt_decode_int(encrypted_query)
    primary_zone_str = ''.join(chr(c) for c in ascii_primary_zone if c != 0) # added filtering for non-char values

    # Display decrypted primary_zone
    print("\nPrimary Zone: ", primary_zone_str)


# <br>
# 
# ## Step 9. Print the result

# In[12]:


# Step 9: Print the result (only if flagged)

if auth_result == "Zones are different. Flagging.":
    string_result = ''.join(chr(c) for c in ascii_result)

    if string_result[0] == 0x00:
        string_result = "primary_zone name not in the database.\n*** Please make sure "
        "to enter the name of a primary_zone\n*** with the "
        "first letter in upper case."
    print("\nQuery Result [Transaction Zone]: ", string_result)


# In[13]:


get_ipython().system('pip install plotly')

import folium
from folium.plugins import AntPath
from IPython.display import display

if auth_result == "Zones are different. Flagging.":
    flagged_zone_id = ''.join(chr(c) for c in ascii_result).strip()
    
    primary_geolocation = tuple(map(float, primary_zone_str.split(',')))
    
    flagged_zone_id_clean = flagged_zone_id.replace('\x00', '').strip()
    flagged_geolocation = tuple(map(float, flagged_zone_id_clean.split(',')))

    # Create a folium map centered between primary_geolocation and flagged_geolocation
    center_location = ((primary_geolocation[0] + flagged_geolocation[0]) / 2, 
                       (primary_geolocation[1] + flagged_geolocation[1]) / 2)
    m = folium.Map(location=center_location, zoom_start=12, tiles='cartodb positron')
    
    # Primary Zone Marker with custom icon and popup
    folium.Marker(
        location=primary_geolocation,
        popup='<strong>Primary Zone</strong>',
        icon=folium.Icon(icon='cloud', color='blue', prefix='fa') # Using Font Awesome icons
    ).add_to(m)

    # Flagged Transaction Marker with custom icon and popup
    folium.Marker(
        location=flagged_geolocation,
        popup='<strong>Flagged Transaction</strong>',
        icon=folium.Icon(icon='exclamation-triangle', color='red', prefix='fa')
    ).add_to(m)
    
    # Distance Circle around primary zone
    folium.Circle(
        location=primary_geolocation,
        radius=1000,  # radius in meters; you can adjust this value
        popup='Proximity Circle',
        color='blue',
        fill=True,
        fill_color='blue'
    ).add_to(m)
    
    # Drawing a route between the primary and flagged transaction
    AntPath(
        locations=[primary_geolocation, flagged_geolocation],
        color='green',
        weight=5
    ).add_to(m)
    
    display(m)



# In[ ]:




