import { calculateEquivalenceClasses, calculateCVSSV4Score } from '../utils/cvssV4Official';
import { CVSSV4Vector } from '../types/cvss';

describe('CVSS v4.0 Equivalence Classes Debug', () => {
  test('Debug equivalence classes for test vectors', () => {
    const testCases = [
      {
        name: 'Critical Network Attack',
        vector: {
          AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N',
          VC: 'H', VI: 'H', VA: 'H', SC: 'H', SI: 'H', SA: 'H'
        } as CVSSV4Vector,
        expectedScore: 10.0
      },
      {
        name: 'High Adjacent Attack',
        vector: {
          AV: 'A', AC: 'L', AT: 'N', PR: 'N', UI: 'N',
          VC: 'H', VI: 'H', VA: 'H', SC: 'N', SI: 'N', SA: 'N'
        } as CVSSV4Vector,
        expectedScore: 8.8
      },
      {
        name: 'Medium Local Attack',
        vector: {
          AV: 'L', AC: 'L', AT: 'N', PR: 'L', UI: 'N',
          VC: 'H', VI: 'L', VA: 'L', SC: 'N', SI: 'N', SA: 'N'
        } as CVSSV4Vector,
        expectedScore: 6.0
      },
      {
        name: 'Low Physical Attack',
        vector: {
          AV: 'P', AC: 'L', AT: 'N', PR: 'N', UI: 'N',
          VC: 'L', VI: 'L', VA: 'L', SC: 'N', SI: 'N', SA: 'N'
        } as CVSSV4Vector,
        expectedScore: 3.4
      }
    ];

    testCases.forEach(({ name, vector, expectedScore }) => {
      const eq = calculateEquivalenceClasses(vector);
      const calculatedScore = calculateCVSSV4Score(vector);
      console.log(`${name}:`);
      console.log(`  Vector: ${JSON.stringify(vector)}`);
      console.log(`  Equivalence Classes: ${eq}`);
      console.log(`  Expected Score: ${expectedScore}`);
      console.log(`  Calculated Score: ${calculatedScore}`);
      console.log('  EQ Breakdown:');
      console.log(`    EQ1 (AV/PR/UI): ${eq[0]}`);
      console.log(`    EQ2 (AC/AT): ${eq[1]}`);
      console.log(`    EQ3 (VC/VI/VA): ${eq[2]}`);
      console.log(`    EQ4 (SC/SI/SA): ${eq[3]}`);
      console.log(`    EQ5 (E): ${eq[4]}`);
      console.log(`    EQ6 (CR/IR/AR): ${eq[5]}`);
      console.log('');
    });
  });
});