LOAD CSV WITH HEADERS FROM 'file:///libraries.csv' AS row
CREATE (:Library {
name: row.name,
groupId: row.groupId,
artifactId: row.artifactId,
version: row.version,
scope: row.scope,
vulnerabilityCount: toInteger(row.vulnerabilityCount),
maxSeverity: row.maxSeverity,
isVulnerable: row.isVulnerable
});

LOAD CSV WITH HEADERS FROM 'file:///relationships.csv' AS row
MATCH (a:Library {name: row.source})
MATCH (b:Library {name: row.target})
CREATE (a)-[:DEPENDS_ON]->(b);
