# Project MAPLE

**Quantum-Proof, Location-Based Credit Transaction Authorization: Pioneering the Future of Secure Transactions**

As credit card fraud looms larger in the digital age, financial giants and consumers alike cry out for advanced, privacy-centric solutions. Enter our Quantum-Proof, Location-Based Credit Transaction Authorization System—a confluence of innovation and security.

**Concept:** Whenever a credit card transaction unfolds, our system is on guard, corroborating the authenticity of the transaction based on its originating location. It cross-references the transaction's geocoordinates with the cardholder's recent whereabouts. Importantly, this scrutiny ensues without unveiling the underlying location data.

**Technology:** Our system employs Fully Homomorphic Encryption (FHE), an encryption paradigm that allows computations on encrypted data, obviating the need for decryption. Thus, it validates the transaction location against the cardholder's without ever exposing either. This transcends conventional security levels while upholding user data sanctity. Furthermore, with quantum computing on the horizon, our quantum-resistant design stands as a bulwark against present and prospective cryptographic threats.

**Integration with POS Systems:** Seamlessly interfacing with Point-of-Sale (POS) units, our system extracts transaction geocoordinates in real-time. This ensures immediate verification against the user's known locations, making transaction approvals swift and secure.

**Value Proposition:** This system heralds a dawn of diminished credit fraud risks. Its adaptive algorithms evolve with a user's location habits, minimizing false alarms while amplifying genuine transaction approvals. The result? An augmented customer experience, bolstered trust, and optimized operational efficiencies.

In the cosmos of luxury and avant-garde tech, Amex's alliance with Prada shines brilliantly. Yet, what if this shimmer could be intensified? Our Quantum-Proof, Location-Based Authorization system envisions this zenith—marrying elite fashion with next-gen security. Visualize an Amex wearable, suffused with the allure of Prada or another luxury brand, but also fortified with our groundbreaking tech. Transactions evolve into harmonious symphonies of style and fortitude. As Amex tailors its future in haute wearable tech, we present the golden thread—a promise to safeguard against the quantum vagaries looming ahead. The ensemble is not just exquisite; it's inviolably robust.


```python
def string_to_ascii(str):
    return [ord(c) for c in str]
```

<br>

## Step 1. Import and initialize


```python
import os
import csv
import copy
import pyhelayers
import utils
print("misc. init ready")
```

    misc. init ready



```python

db_filename = os.path.join("data", "zones", "zones_002.csv") # input database file name
primary_zone = "77.147424,139.930624" # primary_zone to get its transaction_zone
print("input parameters ready.")
```

    input parameters ready.


<br>

## Step 2. Initialize FHE parameters
Note: Although we can hide them away, for demonstration purposes, we show you the parameters (e.g. cyclotomic polynomial) here. The parameters have been chosen to provide a somewhat faster running time with a non-realistic security level. Do not use these parameters in real applications.


```python
conf = pyhelayers.HelibConfig()
conf.p = 127 # Plaintext prime modulus
# this will give 32 slots
conf.m = 128 # Cyclotomic polynomial - defines phi(m)
conf.r = 1 # Hensel lifting
conf.L = 1000 # Number of bits of the modulus chain
conf.c = 2 # Number of columns of Key-Switching matrix
print("configruation ready")
```

    configruation ready


<br>

## Step 3. Initialize HElib BGV Context


```python
utils.start_timer()
he = pyhelayers.HelibBgvContext()
he.init(conf)
print(he)
utils.end_timer("Initializing HE context")
```

    helayers 1.5.2.0
    HELIB BGV context. Context id=1063717799 (WITH SECRET KEY)
    m=128 r=1 L=1000 c=2
    SecurityLevel=0
    Slots=32
    
    Duration of Initializing HE context: 0.009 (s)





    0.009245526001905091




```python
assert(he.get_traits().is_modular_arithmetic)
assert(he.get_traits().arithmetic_modulus >= 127)
print ("asserts passed")
```

    asserts passed


<br>

## Step 4. Read world transaction database from file
The code below will make sure no string is longer than he.slot_count().


```python
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
```

    finished reading database


<br>

## Step 5. Encrypt the database


```python
utils.start_timer()
enc = pyhelayers.Encoder(he)
encrypted_transaction_db = []
for primary_zone_str, transaction_zone_str in transaction_db:
    primary_zone_ctxt = enc.encode_encrypt(primary_zone_str)
    transaction_zone_ctxt = enc.encode_encrypt(transaction_zone_str)
    encrypted_transaction_db.append((primary_zone_ctxt, transaction_zone_ctxt))
utils.end_timer("Encrypting DB")
```

    Duration of Encrypting DB: 0.221 (s)





    0.22136122200026875



<br>

## Step 6. Encrypt the query


```python
utils.start_timer()
primary_zone_ascii = string_to_ascii(primary_zone)
encrypted_query = enc.encode_encrypt(primary_zone_ascii)
utils.end_timer("Encrypting Query")
```

    Duration of Encrypting Query: 0.000 (s)





    0.00045860300451749936



<br>

## Step 7. Perform the encrypted database search


```python
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
```

    Duration of Query search: 12.269 (s)
    Zones are different. Flagging.
    After subtraction: [117   0   2 124 124 125   1   4   3  11 122 121 119   8 119 122   2 124
     126 125  56  55   0   0   0   0   0   0   0   0   0   0]
    After power: [1 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0]
    After negate and add: [0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 1 1 1 1 1 1 1 1 1]
    Zones are different. Flagging.


<br>

## Step 8. Decrypt the result


```python
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
```

    Duration of Decrypting result: 0.000 (s)
    
    Primary Zone:  77.147424,139.930624


<br>

## Step 9. Print the result


```python
# Step 9: Print the result (only if flagged)

if auth_result == "Zones are different. Flagging.":
    string_result = ''.join(chr(c) for c in ascii_result)

    if string_result[0] == 0x00:
        string_result = "primary_zone name not in the database.\n*** Please make sure "
        "to enter the name of a primary_zone\n*** with the "
        "first letter in upper case."
    print("\nQuery Result [Transaction Zone]: ", string_result)
```

    
    Query Result [Transaction Zone]:  -70.155677,-161.231287          



```python
!pip install plotly

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


```

    Defaulting to user installation because normal site-packages is not writeable
    Requirement already satisfied: plotly in /home/user/.local/lib/python3.8/site-packages (5.17.0)
    Requirement already satisfied: tenacity>=6.2.0 in /home/user/.local/lib/python3.8/site-packages (from plotly) (8.2.3)
    Requirement already satisfied: packaging in /usr/local/lib/python3.8/dist-packages (from plotly) (23.0)
    
    [1m[[0m[34;49mnotice[0m[1;39;49m][0m[39;49m A new release of pip is available: [0m[31;49m23.0[0m[39;49m -> [0m[32;49m23.2.1[0m
    [1m[[0m[34;49mnotice[0m[1;39;49m][0m[39;49m To update, run: [0m[32;49mpython3 -m pip install --upgrade pip[0m



<div style="width:100%;"><div style="position:relative;width:100%;height:0;padding-bottom:60%;"><span style="color:#565656">Make this Notebook Trusted to load map: File -> Trust Notebook</span><iframe srcdoc="&lt;!DOCTYPE html&gt;
&lt;html&gt;
&lt;head&gt;

    &lt;meta http-equiv=&quot;content-type&quot; content=&quot;text/html; charset=UTF-8&quot; /&gt;

        &lt;script&gt;
            L_NO_TOUCH = false;
            L_DISABLE_3D = false;
        &lt;/script&gt;

    &lt;style&gt;html, body {width: 100%;height: 100%;margin: 0;padding: 0;}&lt;/style&gt;
    &lt;style&gt;#map {position:absolute;top:0;bottom:0;right:0;left:0;}&lt;/style&gt;
    &lt;script src=&quot;https://cdn.jsdelivr.net/npm/leaflet@1.9.3/dist/leaflet.js&quot;&gt;&lt;/script&gt;
    &lt;script src=&quot;https://code.jquery.com/jquery-1.12.4.min.js&quot;&gt;&lt;/script&gt;
    &lt;script src=&quot;https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/js/bootstrap.bundle.min.js&quot;&gt;&lt;/script&gt;
    &lt;script src=&quot;https://cdnjs.cloudflare.com/ajax/libs/Leaflet.awesome-markers/2.0.2/leaflet.awesome-markers.js&quot;&gt;&lt;/script&gt;
    &lt;link rel=&quot;stylesheet&quot; href=&quot;https://cdn.jsdelivr.net/npm/leaflet@1.9.3/dist/leaflet.css&quot;/&gt;
    &lt;link rel=&quot;stylesheet&quot; href=&quot;https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css&quot;/&gt;
    &lt;link rel=&quot;stylesheet&quot; href=&quot;https://netdna.bootstrapcdn.com/bootstrap/3.0.0/css/bootstrap.min.css&quot;/&gt;
    &lt;link rel=&quot;stylesheet&quot; href=&quot;https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.2.0/css/all.min.css&quot;/&gt;
    &lt;link rel=&quot;stylesheet&quot; href=&quot;https://cdnjs.cloudflare.com/ajax/libs/Leaflet.awesome-markers/2.0.2/leaflet.awesome-markers.css&quot;/&gt;
    &lt;link rel=&quot;stylesheet&quot; href=&quot;https://cdn.jsdelivr.net/gh/python-visualization/folium/folium/templates/leaflet.awesome.rotate.min.css&quot;/&gt;

            &lt;meta name=&quot;viewport&quot; content=&quot;width=device-width,
                initial-scale=1.0, maximum-scale=1.0, user-scalable=no&quot; /&gt;
            &lt;style&gt;
                #map_9f6ef91306d04e82e984ea4dddf02e64 {
                    position: relative;
                    width: 100.0%;
                    height: 100.0%;
                    left: 0.0%;
                    top: 0.0%;
                }
                .leaflet-container { font-size: 1rem; }
            &lt;/style&gt;

    &lt;script src=&quot;https://cdn.jsdelivr.net/npm/leaflet-ant-path@1.1.2/dist/leaflet-ant-path.min.js&quot;&gt;&lt;/script&gt;
&lt;/head&gt;
&lt;body&gt;


            &lt;div class=&quot;folium-map&quot; id=&quot;map_9f6ef91306d04e82e984ea4dddf02e64&quot; &gt;&lt;/div&gt;

&lt;/body&gt;
&lt;script&gt;


            var map_9f6ef91306d04e82e984ea4dddf02e64 = L.map(
                &quot;map_9f6ef91306d04e82e984ea4dddf02e64&quot;,
                {
                    center: [3.495873500000002, -10.650331500000007],
                    crs: L.CRS.EPSG3857,
                    zoom: 12,
                    zoomControl: true,
                    preferCanvas: false,
                }
            );





            var tile_layer_b901c1008b795a2a7ceaffc605500091 = L.tileLayer(
                &quot;https://cartodb-basemaps-{s}.global.ssl.fastly.net/light_all/{z}/{x}/{y}.png&quot;,
                {&quot;attribution&quot;: &quot;\u0026copy; \u003ca target=\&quot;_blank\&quot; href=\&quot;http://www.openstreetmap.org/copyright\&quot;\u003eOpenStreetMap\u003c/a\u003e contributors \u0026copy; \u003ca target=\&quot;_blank\&quot; href=\&quot;http://cartodb.com/attributions\&quot;\u003eCartoDB\u003c/a\u003e, CartoDB \u003ca target=\&quot;_blank\&quot; href =\&quot;http://cartodb.com/attributions\&quot;\u003eattributions\u003c/a\u003e&quot;, &quot;detectRetina&quot;: false, &quot;maxNativeZoom&quot;: 18, &quot;maxZoom&quot;: 18, &quot;minZoom&quot;: 0, &quot;noWrap&quot;: false, &quot;opacity&quot;: 1, &quot;subdomains&quot;: &quot;abc&quot;, &quot;tms&quot;: false}
            ).addTo(map_9f6ef91306d04e82e984ea4dddf02e64);


            var marker_e1c8809121bc8fa3a473406c8029e45f = L.marker(
                [77.147424, 139.930624],
                {}
            ).addTo(map_9f6ef91306d04e82e984ea4dddf02e64);


            var icon_def9e12020e7be8a6dc47d17847415b1 = L.AwesomeMarkers.icon(
                {&quot;extraClasses&quot;: &quot;fa-rotate-0&quot;, &quot;icon&quot;: &quot;cloud&quot;, &quot;iconColor&quot;: &quot;white&quot;, &quot;markerColor&quot;: &quot;blue&quot;, &quot;prefix&quot;: &quot;fa&quot;}
            );
            marker_e1c8809121bc8fa3a473406c8029e45f.setIcon(icon_def9e12020e7be8a6dc47d17847415b1);


        var popup_99140700b201066c3099d6925e98d1f3 = L.popup({&quot;maxWidth&quot;: &quot;100%&quot;});



                var html_cf5942b476eafabe27ef1cf5fddb580e = $(`&lt;div id=&quot;html_cf5942b476eafabe27ef1cf5fddb580e&quot; style=&quot;width: 100.0%; height: 100.0%;&quot;&gt;&lt;strong&gt;Primary Zone&lt;/strong&gt;&lt;/div&gt;`)[0];
                popup_99140700b201066c3099d6925e98d1f3.setContent(html_cf5942b476eafabe27ef1cf5fddb580e);



        marker_e1c8809121bc8fa3a473406c8029e45f.bindPopup(popup_99140700b201066c3099d6925e98d1f3)
        ;




            var marker_63cb87e71416ee6cf1ac5d0bcb17bb48 = L.marker(
                [-70.155677, -161.231287],
                {}
            ).addTo(map_9f6ef91306d04e82e984ea4dddf02e64);


            var icon_e719acf80cd5c40bce90fbfc77704db9 = L.AwesomeMarkers.icon(
                {&quot;extraClasses&quot;: &quot;fa-rotate-0&quot;, &quot;icon&quot;: &quot;exclamation-triangle&quot;, &quot;iconColor&quot;: &quot;white&quot;, &quot;markerColor&quot;: &quot;red&quot;, &quot;prefix&quot;: &quot;fa&quot;}
            );
            marker_63cb87e71416ee6cf1ac5d0bcb17bb48.setIcon(icon_e719acf80cd5c40bce90fbfc77704db9);


        var popup_df22a08bdc6453ff02a01319d43e4fe3 = L.popup({&quot;maxWidth&quot;: &quot;100%&quot;});



                var html_18de291fc22853577603f3a46ed1f446 = $(`&lt;div id=&quot;html_18de291fc22853577603f3a46ed1f446&quot; style=&quot;width: 100.0%; height: 100.0%;&quot;&gt;&lt;strong&gt;Flagged Transaction&lt;/strong&gt;&lt;/div&gt;`)[0];
                popup_df22a08bdc6453ff02a01319d43e4fe3.setContent(html_18de291fc22853577603f3a46ed1f446);



        marker_63cb87e71416ee6cf1ac5d0bcb17bb48.bindPopup(popup_df22a08bdc6453ff02a01319d43e4fe3)
        ;




            var circle_3752a5257bcb68e8bb8a8bc916b5a13c = L.circle(
                [77.147424, 139.930624],
                {&quot;bubblingMouseEvents&quot;: true, &quot;color&quot;: &quot;blue&quot;, &quot;dashArray&quot;: null, &quot;dashOffset&quot;: null, &quot;fill&quot;: true, &quot;fillColor&quot;: &quot;blue&quot;, &quot;fillOpacity&quot;: 0.2, &quot;fillRule&quot;: &quot;evenodd&quot;, &quot;lineCap&quot;: &quot;round&quot;, &quot;lineJoin&quot;: &quot;round&quot;, &quot;opacity&quot;: 1.0, &quot;radius&quot;: 1000, &quot;stroke&quot;: true, &quot;weight&quot;: 3}
            ).addTo(map_9f6ef91306d04e82e984ea4dddf02e64);


        var popup_58dac14c7edf2936e74e1e2f94282528 = L.popup({&quot;maxWidth&quot;: &quot;100%&quot;});



                var html_02e33e88d8d6782299cccfa0544ced00 = $(`&lt;div id=&quot;html_02e33e88d8d6782299cccfa0544ced00&quot; style=&quot;width: 100.0%; height: 100.0%;&quot;&gt;Proximity Circle&lt;/div&gt;`)[0];
                popup_58dac14c7edf2936e74e1e2f94282528.setContent(html_02e33e88d8d6782299cccfa0544ced00);



        circle_3752a5257bcb68e8bb8a8bc916b5a13c.bindPopup(popup_58dac14c7edf2936e74e1e2f94282528)
        ;




            ant_path_c0b5feb1958a0177cc57aba526175f45 = L.polyline.antPath(
              [[77.147424, 139.930624], [-70.155677, -161.231287]],
              {&quot;bubblingMouseEvents&quot;: true, &quot;color&quot;: &quot;green&quot;, &quot;dashArray&quot;: [10, 20], &quot;dashOffset&quot;: null, &quot;delay&quot;: 400, &quot;fill&quot;: false, &quot;fillColor&quot;: &quot;green&quot;, &quot;fillOpacity&quot;: 0.2, &quot;fillRule&quot;: &quot;evenodd&quot;, &quot;hardwareAcceleration&quot;: false, &quot;lineCap&quot;: &quot;round&quot;, &quot;lineJoin&quot;: &quot;round&quot;, &quot;noClip&quot;: false, &quot;opacity&quot;: 0.5, &quot;paused&quot;: false, &quot;pulseColor&quot;: &quot;#FFFFFF&quot;, &quot;reverse&quot;: false, &quot;smoothFactor&quot;: 1.0, &quot;stroke&quot;: true, &quot;weight&quot;: 5}
        ).addTo(map_9f6ef91306d04e82e984ea4dddf02e64);

&lt;/script&gt;
&lt;/html&gt;" style="position:absolute;width:100%;height:100%;left:0;top:0;border:none !important;" allowfullscreen webkitallowfullscreen mozallowfullscreen></iframe></div></div>



```python

```
