// Base URL for API requests
const API_BASE_URL = '/api';

// Helper function to display results
function displayResult(elementId, data, isError = false) {
  const resultElement = document.getElementById(elementId);
  resultElement.innerHTML = '';
  
  if (isError) {
    resultElement.style.color = 'red';
  } else {
    resultElement.style.color = 'black';
  }
  
  if (typeof data === 'object') {
    resultElement.innerText = JSON.stringify(data, null, 2);
  } else {
    resultElement.innerText = data;
  }
}

// Helper function to make API requests
async function apiRequest(endpoint, method, data = null, headers = {}) {
  try {
    const options = {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...headers
      }
    };
    
    if (data && (method === 'POST' || method === 'PUT')) {
      options.body = JSON.stringify(data);
    }
    
    const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
    const responseData = await response.json();
    
    if (!response.ok) {
      throw new Error(responseData.message || 'API request failed');
    }
    
    return responseData;
  } catch (error) {
    throw error;
  }
}

// Hash content using SHA-256
function hashContent(content) {
  return 'sha256:' + CryptoJS.SHA256(content).toString(CryptoJS.enc.Hex);
}

// Create Author Form
document.getElementById('create-author-form').addEventListener('submit', async function(e) {
  e.preventDefault();
  
  try {
    const name = document.getElementById('author-name').value;
    const description = document.getElementById('author-description').value;
    const url = document.getElementById('author-url').value;
    const keyType = document.getElementById('author-key-type').value;
    const keyAlgorithm = document.getElementById('author-key-algorithm').value;
    const apiKey = document.getElementById('general-api-key').value;
    
    const data = {
      name,
      description,
      url,
      keyType,
      keyAlgorithm
    };
    
    const result = await apiRequest('/authors', 'POST', data, {
      'X-API-KEY': apiKey
    });
    
    displayResult('create-author-result', result);
  } catch (error) {
    displayResult('create-author-result', error.message, true);
  }
});

// Get Authors Form
document.getElementById('get-authors-form').addEventListener('submit', async function(e) {
  e.preventDefault();
  
  try {
    const nameFilter = document.getElementById('authors-name-filter').value;
    const keyTypeFilter = document.getElementById('authors-key-type-filter').value;
    const apiKey = document.getElementById('authors-api-key').value;
    
    let endpoint = '/authors?';
    if (nameFilter) endpoint += `name=${encodeURIComponent(nameFilter)}&`;
    if (keyTypeFilter) endpoint += `keyType=${encodeURIComponent(keyTypeFilter)}&`;
    
    const result = await apiRequest(endpoint, 'GET', null, {
      'X-API-KEY': apiKey
    });
    
    displayResult('get-authors-result', result);
  } catch (error) {
    displayResult('get-authors-result', error.message, true);
  }
});

// Sign Content Form
document.getElementById('sign-content-form').addEventListener('submit', async function(e) {
  e.preventDefault();
  
  try {
    const content = document.getElementById('content-text').value;
    const domain = document.getElementById('content-domain').value;
    const claimsJson = document.getElementById('content-claims').value;
    const authorId = document.getElementById('author-id').value;
    const authorApiKey = document.getElementById('author-api-key').value;
    
    // Hash the content
    const contentHash = hashContent(content);
    
    // Parse claims
    let claims;
    try {
      claims = JSON.parse(claimsJson);
    } catch (error) {
      throw new Error('Invalid JSON for claims');
    }
    
    const data = {
      contentHash,
      domain,
      claims
    };
    
    const result = await apiRequest('/content/sign', 'POST', data, {
      'X-AUTHOR-API-KEY': authorApiKey
    });
    
    displayResult('sign-content-result', result);
  } catch (error) {
    displayResult('sign-content-result', error.message, true);
  }
});

// Verify Content Form
document.getElementById('verify-content-form').addEventListener('submit', async function(e) {
  e.preventDefault();
  
  try {
    const contentHash = document.getElementById('verify-content-hash').value;
    const domain = document.getElementById('verify-domain').value;
    const authorId = document.getElementById('verify-author-id').value;
    const signature = document.getElementById('verify-signature').value;
    
    const data = {
      contentHash,
      domain,
      authorId,
      signature
    };
    
    const result = await apiRequest('/content/verify', 'POST', data);
    
    displayResult('verify-content-result', result);
  } catch (error) {
    displayResult('verify-content-result', error.message, true);
  }
});

// Search Public Keys Form
document.getElementById('search-keys-form').addEventListener('submit', async function(e) {
  e.preventDefault();
  
  try {
    const authorName = document.getElementById('keys-author-name').value;
    const keyType = document.getElementById('keys-key-type').value;
    const minTrustScore = document.getElementById('keys-min-trust-score').value;
    
    let endpoint = '/directory/keys?';
    if (authorName) endpoint += `authorName=${encodeURIComponent(authorName)}&`;
    if (keyType) endpoint += `keyType=${encodeURIComponent(keyType)}&`;
    if (minTrustScore) endpoint += `minTrustScore=${encodeURIComponent(minTrustScore)}&`;
    
    const result = await apiRequest(endpoint, 'GET');
    
    displayResult('search-keys-result', result);
  } catch (error) {
    displayResult('search-keys-result', error.message, true);
  }
});

// Search Signed Content Form
document.getElementById('search-content-form').addEventListener('submit', async function(e) {
  e.preventDefault();
  
  try {
    const contentHash = document.getElementById('content-hash').value;
    const authorId = document.getElementById('content-author-id').value;
    const domain = document.getElementById('content-domain-filter').value;
    
    let endpoint = '/directory/content?';
    if (contentHash) endpoint += `contentHash=${encodeURIComponent(contentHash)}&`;
    if (authorId) endpoint += `authorId=${encodeURIComponent(authorId)}&`;
    if (domain) endpoint += `domain=${encodeURIComponent(domain)}&`;
    
    const result = await apiRequest(endpoint, 'GET');
    
    displayResult('search-content-result', result);
  } catch (error) {
    displayResult('search-content-result', error.message, true);
  }
});

// Create Vote Form
document.getElementById('create-vote-form').addEventListener('submit', async function(e) {
  e.preventDefault();
  
  try {
    const userId = document.getElementById('vote-user-id').value;
    const targetType = document.getElementById('vote-target-type').value;
    const targetId = document.getElementById('vote-target-id').value;
    const voteType = document.getElementById('vote-type').value;
    const reason = document.getElementById('vote-reason').value;
    const apiKey = document.getElementById('vote-api-key').value;
    
    const data = {
      userId,
      targetType,
      targetId,
      voteType,
      reason
    };
    
    const result = await apiRequest('/votes', 'POST', data, {
      'X-API-KEY': apiKey
    });
    
    displayResult('create-vote-result', result);
  } catch (error) {
    displayResult('create-vote-result', error.message, true);
  }
});

// Get Vote Statistics Form
document.getElementById('vote-stats-form').addEventListener('submit', async function(e) {
  e.preventDefault();
  
  try {
    const targetType = document.getElementById('stats-target-type').value;
    const targetId = document.getElementById('stats-target-id').value;
    
    const endpoint = `/votes/stats/${targetType}/${targetId}`;
    
    const result = await apiRequest(endpoint, 'GET');
    
    displayResult('vote-stats-result', result);
  } catch (error) {
    displayResult('vote-stats-result', error.message, true);
  }
});