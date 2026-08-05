package Learner;

import io.github.protocolfuzzing.protocolstatefuzzer.components.learner.*;
import io.github.protocolfuzzing.protocolstatefuzzer.components.learner.statistics.MealyMachineWrapper;
import io.github.protocolfuzzing.protocolstatefuzzer.entrypoints.*;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.difftester.DiffTestResult;
import io.github.protocolfuzzing.protocolstatefuzzer.statefuzzer.difftester.DivergenceRecord;
import java.util.List;

public class Main {

    public static void main(String[] args) {
        // Multibuilder implements all necessary builders
        MultiBuilder mb = new MultiBuilder();

        // single parentLogger, if Main resides in the outermost package
        String[] parentLoggers = { Main.class.getPackageName() };

        CommandLineParser<
            MealyMachineWrapper<TCPInput, TCPOutput>
        > commandLineParser = new CommandLineParser<>(mb, mb, mb, mb, mb, mb);

        commandLineParser.setExternalParentLoggers(parentLoggers);

        // Runs the requested command
        List<
            ProcessResult<MealyMachineWrapper<TCPInput, TCPOutput>>
        > results = commandLineParser.process(args, true);

        // Prints the result only for diff-test
        for (
            ProcessResult<MealyMachineWrapper<TCPInput, TCPOutput>> result :
            results
        ) {
            printDiffTestResult(result);
        }
    }

    private static void printDiffTestResult(
        ProcessResult<MealyMachineWrapper<TCPInput, TCPOutput>> result
    ) {
        // Ignore normal learning results
        if (!result.hasDiffTestResult()) {
            return;
        }

        DiffTestResult diffResult = result.getDiffTestResult();

        // The comparison could not finish
        if (diffResult.isEmpty()) {
            System.out.println("Differential testing failed.");
            return;
        }

        // No differences were found
        if (diffResult.areModelsEquivalent()) {
            System.out.println("The models are equivalent.");
            return;
        }

        System.out.println(
            "Number of differences: "
                + diffResult.getDivergences().size()
        );

        int number = 1;

        for (
            DivergenceRecord<String, String> difference :
            diffResult.getDivergences()
        ) {
            System.out.println();
            System.out.println("Difference " + number);

            System.out.println(
                "Input sequence: "
                    + difference.witnessSequence()
            );

            System.out.println(
                "Model A output: "
                    + difference.outputA()
            );

            System.out.println(
                "Model B output: "
                    + difference.outputB()
            );

            number++;
        }
    }
}
