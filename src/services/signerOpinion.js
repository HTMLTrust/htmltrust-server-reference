const SignerVote = require('../models/SignerVote');
const SignerReport = require('../models/SignerReport');

/** Derive current opinion totals from immutable reports and current votes. */
async function signerOpinion(signerId) {
  const [voteTotals, reportCount] = await Promise.all([
    SignerVote.aggregate([
      { $match: { signerId } },
      {
        $group: {
          _id: null,
          count: { $sum: 1 },
          balance: {
            $sum: { $cond: [{ $eq: ['$voteType', 'TRUST'] }, 1, -1] },
          },
        },
      },
    ]),
    SignerReport.countDocuments({ signerId }),
  ]);
  return {
    voteCount: voteTotals[0]?.count || 0,
    voteDelta: (voteTotals[0]?.balance || 0) * 0.01,
    reportCount,
  };
}

function applySignerOpinion(base, opinion) {
  return {
    score: Math.max(0, Math.min(1, base.trustScore + opinion.voteDelta - opinion.reportCount * 0.05)),
    reports: (base.reports || 0) + opinion.reportCount,
    verifiedSignatures: base.verifiedSignatures || 0,
  };
}

module.exports = { applySignerOpinion, signerOpinion };
