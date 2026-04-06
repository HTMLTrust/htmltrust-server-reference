const Author = require('../models/Author');
const Key = require('../models/Key');
const ContentSignature = require('../models/ContentSignature');
const ContentOccurrence = require('../models/ContentOccurrence');
const { signContent, verifySignature } = require('../utils/crypto');

/**
 * @desc    Sign content
 * @route   POST /api/content/sign
 * @access  Private (Author API Key)
 */
exports.signContent = async (req, res) => {
  try {
    const { contentHash, domain, claims } = req.body;
    const author = req.author;

    // Get author's private key
    const key = await Key.findOne({ authorId: author._id }).select('+privateKey');
    
    if (!key) {
      return res.status(404).json({
        code: 'NOT_FOUND',
        message: 'Key not found for this author'
      });
    }

    // Create data string to sign (contentHash + domain + authorId)
    const dataToSign = `${contentHash}:${domain}:${author._id}`;
    
    // Sign the data
    const signature = signContent(dataToSign, key.privateKey, key.algorithm);

    // Check if a signature already exists for this content, domain, and author
    let contentSignature = await ContentSignature.findOne({
      contentHash,
      domain,
      authorId: author._id
    });

    if (contentSignature) {
      // Update existing signature
      contentSignature.signature = signature;
      contentSignature.claims = claims;
      contentSignature.occurrences += 1;
      await contentSignature.save();
    } else {
      // Create new signature
      contentSignature = await ContentSignature.create({
        contentHash,
        domain,
        authorId: author._id,
        keyId: key._id,
        signature,
        claims
      });
    }

    // Return the signature
    res.status(201).json({
      contentHash,
      domain,
      authorId: author._id,
      signature,
      claims,
      createdAt: contentSignature.createdAt
    });
  } catch (error) {
    console.error('Sign content error:', error);
    res.status(400).json({
      code: 'BAD_REQUEST',
      message: error.message
    });
  }
};

/**
 * @desc    Verify content signature
 * @route   POST /api/content/verify
 * @access  Public
 */
exports.verifyContent = async (req, res) => {
  try {
    const { contentHash, domain, authorId, signature } = req.body;

    // Get author
    const author = await Author.findById(authorId);
    
    if (!author) {
      return res.status(404).json({
        code: 'NOT_FOUND',
        message: 'Author not found'
      });
    }

    // Get author's public key
    const key = await Key.findOne({ authorId });
    
    if (!key) {
      return res.status(404).json({
        code: 'NOT_FOUND',
        message: 'Public key not found'
      });
    }

    // Create data string that was signed
    const dataToVerify = `${contentHash}:${domain}:${authorId}`;
    
    // Verify the signature
    const valid = verifySignature(dataToVerify, signature, key.publicKey, key.algorithm);

    // Get claims if signature is valid
    let claims = {};
    if (valid) {
      // Find the content signature
      const contentSignature = await ContentSignature.findOne({
        contentHash,
        domain,
        authorId
      });
      
      if (contentSignature) {
        claims = contentSignature.claims;
        
        // Increment verified signatures count
        key.verifiedSignatures += 1;
        await key.save();
      }
    }

    // Return verification result
    res.status(200).json({
      valid,
      author,
      claims
    });
  } catch (error) {
    console.error('Verify content error:', error);
    res.status(400).json({
      code: 'BAD_REQUEST',
      message: error.message
    });
  }
};

/**
 * @desc    Register content occurrence
 * @route   POST /api/content/occurrences
 * @access  Private (General API Key)
 */
exports.registerOccurrence = async (req, res) => {
  try {
    const { contentHash, url, domain, authorId, signature } = req.body;

    // Verify the signature if provided
    let signatureValid = false;
    let signatureId = null;
    
    if (signature && authorId) {
      // Get author's public key
      const key = await Key.findOne({ authorId });
      
      if (key) {
        // Create data string that was signed
        const dataToVerify = `${contentHash}:${domain}:${authorId}`;
        
        // Verify the signature
        signatureValid = verifySignature(dataToVerify, signature, key.publicKey, key.algorithm);
        
        if (signatureValid) {
          // Find or create the content signature
          let contentSignature = await ContentSignature.findOne({
            contentHash,
            domain,
            authorId
          });
          
          if (!contentSignature) {
            contentSignature = await ContentSignature.create({
              contentHash,
              domain,
              authorId,
              keyId: key._id,
              signature
            });
          }
          
          signatureId = contentSignature._id;
        }
      }
    }

    // Check if occurrence already exists
    let occurrence = await ContentOccurrence.findOne({
      signatureId,
      url
    });

    if (occurrence) {
      // Update last seen timestamp
      occurrence.lastSeen = Date.now();
      occurrence.signatureValid = signatureValid;
      await occurrence.save();
    } else {
      // Create new occurrence
      occurrence = await ContentOccurrence.create({
        signatureId,
        url,
        domain,
        signatureValid
      });
    }

    res.status(201).json(occurrence);
  } catch (error) {
    console.error('Register occurrence error:', error);
    res.status(400).json({
      code: 'BAD_REQUEST',
      message: error.message
    });
  }
};