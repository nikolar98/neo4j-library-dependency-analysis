MATCH (l:Library)
WHERE l.vulnerabilityCount > 0
RETURN l.name, l.vulnerabilityCount, l.maxSeverity
ORDER BY l.vulnerabilityCount DESC, l.maxSeverity;

MATCH (l:Library)
WHERE l.vulnerabilityCount > 0
RETURN COUNT(l) AS vulnerableLibraries;

CREATE (:CWE {id:'CWE-770', name:'Allocation of Resources Without Limits or Throttling'});
CREATE (:CWE {id:'CWE-284', name:'Improper Access Control'});
CREATE (:CWE {id:'CWE-79', name:'Improper Neutralization of Input During Web Page Generation'});
CREATE (:CWE {id:'CWE-20', name:'Improper Input Validation'});

MATCH (l:Library {name:'com.fasterxml.jackson.core:jackson-core'}), (c:CWE {id:'CWE-770'})
CREATE (l)-[:HAS_CWE]->(c);

MATCH (l:Library {name:'commons-beanutils:commons-beanutils'}), (c:CWE {id:'CWE-284'})
CREATE (l)-[:HAS_CWE]->(c);

MATCH (l:Library {name:'net.sf.jasperreports:jasperreports'}), (c:CWE {id:'CWE-79'})
CREATE (l)-[:HAS_CWE]->(c);

MATCH (l:Library {name:'ch.qos.logback:logback-core'}), (c:CWE {id:'CWE-20'})
CREATE (l)-[:HAS_CWE]->(c);

MERGE (:CAPEC {id:'CAPEC-63', name:'Cross-Site Scripting'});

MATCH (c:CWE {id:'CWE-79'}), (a:CAPEC {id:'CAPEC-63'})
MERGE (c)-[:RELATED_TO_CAPEC]->(a);

MERGE (:Mitigation {name:'Output Encoding'});
MERGE (:Mitigation {name:'Input Validation'});

MATCH (c:CWE {id:'CWE-79'})
MATCH (m1:Mitigation {name:'Output Encoding'})
MERGE (c)-[:MITIGATED_BY]->(m1);

MATCH (c:CWE {id:'CWE-79'})
MATCH (m2:Mitigation {name:'Input Validation'})
MERGE (c)-[:MITIGATED_BY]->(m2);

CALL gds.degree.stream('libraryGraph')
YIELD nodeId, score
WITH gds.util.asNode(nodeId) AS node, score
MATCH (node)-[:HAS_CWE]->(c:CWE)-[:RELATED_TO_CAPEC]->(a:CAPEC)
RETURN node.name AS library,
score,
node.maxSeverity AS severity,
c.id AS cweId,
c.name AS cweName,
a.id AS capecId,
a.name AS attack
ORDER BY score DESC, library, cweId;
