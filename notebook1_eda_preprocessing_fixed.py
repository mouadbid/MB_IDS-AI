#!/usr/bin/env python
# coding: utf-8

# # IDS Project — Notebook 1: EDA & Preprocessing
# **Dataset:** CICIDS 2017  
# **Hardware:** i9-13950HX + RTX 3500 Ada

# ## 1. Imports

# In[1]:


import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
import warnings
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pickle

warnings.filterwarnings('ignore')
pd.set_option('display.max_columns', 50)
pd.set_option('display.float_format', '{:.4f}'.format)

print('Libraries loaded.')


# ## 2. Load All CSV Files

# In[2]:


DATA_DIR = '.'

csv_files = [
    'Monday-WorkingHours.pcap_ISCX.csv',
    'Tuesday-WorkingHours.pcap_ISCX.csv',
    'Wednesday-workingHours.pcap_ISCX.csv',
    'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    'Friday-WorkingHours-Morning.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
]

dfs = []
for f in csv_files:
    path = os.path.join(DATA_DIR, f)
    df_temp = pd.read_csv(path, low_memory=False)
    print(f'{f}: {df_temp.shape}')
    dfs.append(df_temp)

df = pd.concat(dfs, ignore_index=True)
print(f'\nCombined shape: {df.shape}')


# ## 3. Basic Inspection

# In[3]:


df.columns = df.columns.str.strip()

print('Shape:', df.shape)
print('\nColumn names:')
print(df.columns.tolist())


# In[4]:


df.head()


# In[5]:


df.dtypes.value_counts()


# ## 4. Label Distribution

# In[6]:


label_counts = df['Label'].value_counts()
print('Attack type counts:')
print(label_counts)
print(f'\nTotal classes: {label_counts.shape[0]}')


# In[7]:


fig, axes = plt.subplots(1, 2, figsize=(16, 5))

label_counts.plot(kind='bar', ax=axes[0], color='steelblue', edgecolor='black')
axes[0].set_title('Sample Count per Attack Type')
axes[0].set_xlabel('Attack Type')
axes[0].set_ylabel('Count')
axes[0].tick_params(axis='x', rotation=45)

label_counts.head(10).plot(kind='pie', ax=axes[1], autopct='%1.1f%%')
axes[1].set_title('Distribution (Top 10)')
axes[1].set_ylabel('')

plt.tight_layout()
plt.savefig('label_distribution.png', dpi=150)
plt.show()


# ## 5. Missing Values & Infinite Values

# In[8]:


null_counts = df.isnull().sum()
print('Columns with nulls:')
print(null_counts[null_counts > 0])

numeric_cols = df.select_dtypes(include=[np.number]).columns
inf_counts = np.isinf(df[numeric_cols]).sum()
print('\nColumns with infinity values:')
print(inf_counts[inf_counts > 0])


# In[9]:


df.replace([np.inf, -np.inf], np.nan, inplace=True)
rows_before = len(df)
df.dropna(inplace=True)
print(f'Dropped {rows_before - len(df)} rows with NaN/Inf')
print(f'Remaining rows: {len(df)}')


# ## 6. Statistical Summary

# In[10]:


df[numeric_cols].describe().T.sort_values('std', ascending=False).head(20)


# ## 7. Correlation Heatmap (Top 20 Features)

# In[11]:


top_var_cols = df[numeric_cols].var().sort_values(ascending=False).head(20).index

plt.figure(figsize=(14, 10))
corr = df[top_var_cols].corr()
mask = np.triu(np.ones_like(corr, dtype=bool))
sns.heatmap(corr, mask=mask, cmap='coolwarm', center=0,
            linewidths=0.5, annot=False)
plt.title('Correlation Matrix — Top 20 Variance Features')
plt.tight_layout()
plt.savefig('correlation_heatmap.png', dpi=150)
plt.show()


# ## 8. Feature Distributions by Attack Type (Sample)

# In[12]:


# pd.concat avoids pandas 2.x groupby Label-drop bug
sample = pd.concat([
    grp.sample(min(500, len(grp)), random_state=42)
    for _, grp in df.groupby('Label')
], ignore_index=True)

key_features = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
                'Flow Bytes/s', 'Flow Packets/s']
key_features = [f for f in key_features if f in df.columns]

fig, axes = plt.subplots(1, len(key_features), figsize=(5 * len(key_features), 4))

for ax, feat in zip(axes, key_features):
    for label in sample['Label'].unique():
        vals = sample[sample['Label'] == label][feat].dropna()
        vals = vals[np.isfinite(vals)]
        if len(vals) > 0:
            ax.hist(np.log1p(np.abs(vals)), bins=30, alpha=0.4, label=label, density=True)
    ax.set_title(feat)
    ax.set_xlabel('log1p(|value|)')

axes[-1].legend(loc='upper right', fontsize=7, bbox_to_anchor=(1.5, 1))
plt.suptitle('Feature Distributions by Attack Type (log scale)', y=1.02)
plt.tight_layout()
plt.savefig('feature_distributions.png', dpi=150, bbox_inches='tight')
plt.show()


# ## 9. Label Encoding

# In[13]:


df['label_binary'] = (df['Label'] != 'BENIGN').astype(int)
print('Binary label distribution:')
print(df['label_binary'].value_counts())

le = LabelEncoder()
df['label_encoded'] = le.fit_transform(df['Label'])

print('\nClass mapping:')
for i, cls in enumerate(le.classes_):
    print(f'  {i}: {cls}')

with open('label_encoder.pkl', 'wb') as f:
    pickle.dump(le, f)
print('\nLabel encoder saved → label_encoder.pkl')


# ## 10. Feature Selection via Random Forest Importance

# In[14]:


# pd.concat avoids pandas 2.x groupby Label-drop bug
sample_for_importance = pd.concat([
    grp.sample(min(2000, len(grp)), random_state=42)
    for _, grp in df.groupby('Label')
], ignore_index=True)

feature_cols = [c for c in numeric_cols if c not in ['label_binary', 'label_encoded']]
X_sample = sample_for_importance[feature_cols]
y_sample = sample_for_importance['label_encoded']

rf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
rf.fit(X_sample, y_sample)

importances = pd.Series(rf.feature_importances_, index=feature_cols)
top_features = importances.sort_values(ascending=False).head(30)

print('Top 30 features by importance:')
print(top_features)


# In[15]:


plt.figure(figsize=(10, 8))
top_features.plot(kind='barh', color='steelblue', edgecolor='black')
plt.title('Top 30 Feature Importances (Random Forest)')
plt.xlabel('Importance')
plt.gca().invert_yaxis()
plt.tight_layout()
plt.savefig('feature_importance.png', dpi=150)
plt.show()


# ## 11. Prepare Final Dataset

# In[16]:


TOP_N = 30
selected_features = top_features.head(TOP_N).index.tolist()
print(f'Selected {TOP_N} features: {selected_features}')

X = df[selected_features].values
y_binary = df['label_binary'].values
y_multi  = df['label_encoded'].values


# In[17]:


scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

with open('scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)
print('Scaler saved → scaler.pkl')

with open('selected_features.pkl', 'wb') as f:
    pickle.dump(selected_features, f)
print('Feature list saved → selected_features.pkl')


# In[18]:


X_train, X_test, y_train_b, y_test_b, y_train_m, y_test_m = train_test_split(
    X_scaled, y_binary, y_multi,
    test_size=0.2, random_state=42, stratify=y_binary
)

print(f'Train: {X_train.shape}  |  Test: {X_test.shape}')
print(f'Train attack ratio: {y_train_b.mean():.3f}')
print(f'Test  attack ratio: {y_test_b.mean():.3f}')


# In[19]:


np.save('X_train.npy', X_train)
np.save('X_test.npy', X_test)
np.save('y_train_binary.npy', y_train_b)
np.save('y_test_binary.npy', y_test_b)
np.save('y_train_multi.npy', y_train_m)
np.save('y_test_multi.npy', y_test_m)

print('All splits saved. Ready for Notebook 2.')


# ## Summary
# 
# | Step | Result |
# |------|--------|
# | Raw rows | ~2.8M |
# | After cleaning | see above |
# | Features selected | 30 (by RF importance) |
# | Output files | `X_train.npy`, `X_test.npy`, `y_*`, `scaler.pkl`, `label_encoder.pkl`, `selected_features.pkl` |
# 
# **Next:** Notebook 2 — Model Training
