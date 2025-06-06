import { CVSS40 } from '../utils/cvssV4FullImplementation';
import { calculateCVSSV4Score, generateV4VectorString } from '../utils/cvssV4Calculator';
import { CVSSV4Vector } from '../types/cvss';

describe('CVSS v4.0 Equivalence Classes Debug', () => {
  test('Debug equivalence classes for test vectors', () => {
    const testCases = [
      {
        name: 'Critical Network Attack',
        vector: {
          AV: 'N',
          AC: 'L',
          AT: 'N',
          PR: 'N',
          UI: 'N',
          VC: 'H',
          VI: 'H',
          VA: 'H',
          SC: 'H',
          SI: 'H',
          SA: 'H',
        } as CVSSV4Vector,
        expectedScore: 10.0,
      },
      {
        name: 'High Adjacent Attack',
        vector: {
          AV: 'A',
          AC: 'L',
          AT: 'N',
          PR: 'N',
          UI: 'N',
          VC: 'H',
          VI: 'H',
          VA: 'H',
          SC: 'N',
          SI: 'N',
          SA: 'N',
        } as CVSSV4Vector,
        expectedScore: 8.8,
      },
      {
        name: 'Medium Local Attack',
        vector: {
          AV: 'L',
          AC: 'L',
          AT: 'N',
          PR: 'L',
          UI: 'N',
          VC: 'H',
          VI: 'L',
          VA: 'L',
          SC: 'N',
          SI: 'N',
          SA: 'N',
        } as CVSSV4Vector,
        expectedScore: 6.0,
      },
      {
        name: 'Low Physical Attack',
        vector: {
          AV: 'P',
          AC: 'L',
          AT: 'N',
          PR: 'N',
          UI: 'N',
          VC: 'L',
          VI: 'L',
          VA: 'L',
          SC: 'N',
          SI: 'N',
          SA: 'N',
        } as CVSSV4Vector,
        expectedScore: 3.4,
      },
    ];

    testCases.forEach(({ name, vector, expectedScore }) => {
      const vectorString = generateV4VectorString(vector);
      const cvss = new CVSS40(vectorString);
      const calculatedScore = calculateCVSSV4Score(vector);
      const eq = cvss.vector.equivalentClasses;

      // eslint-disable-next-line no-console
      console.log(`${name}:`);
      // eslint-disable-next-line no-console
      console.log(`  Vector: ${vectorString}`);
      // eslint-disable-next-line no-console
      console.log(`  Equivalence Classes: ${eq}`);
      // eslint-disable-next-line no-console
      console.log(`  Expected Score: ${expectedScore}`);
      // eslint-disable-next-line no-console
      console.log(`  Calculated Score: ${calculatedScore.baseScore}`);
      // eslint-disable-next-line no-console
      console.log('  EQ Breakdown:');
      // eslint-disable-next-line no-console
      console.log(`    EQ1 (AV/PR/UI): ${eq[0]}`);
      // eslint-disable-next-line no-console
      console.log(`    EQ2 (AC/AT): ${eq[1]}`);
      // eslint-disable-next-line no-console
      console.log(`    EQ3 (VC/VI/VA): ${eq[2]}`);
      // eslint-disable-next-line no-console
      console.log(`    EQ4 (SC/SI/SA): ${eq[3]}`);
      // eslint-disable-next-line no-console
      console.log(`    EQ5 (E): ${eq[4]}`);
      // eslint-disable-next-line no-console
      console.log(`    EQ6 (CR/IR/AR): ${eq[5]}`);
      // eslint-disable-next-line no-console
      console.log('');
    });
  });
});
