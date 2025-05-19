using Spectre.Console;
using Spectre.Console.Rendering;

namespace ps4_eboot_dlc_patcher;
internal class ConsoleUi
{
    public static void LogError(string message)
    {
        AnsiConsole.MarkupLineInterpolated($"[red][[ERROR]] {message}[/]");
    }

    public static void LogWarning(string message)
    {
        AnsiConsole.MarkupLineInterpolated($"[yellow][[WARN]] {message}[/]");
    }

    public static void LogInfo(string message)
    {
        AnsiConsole.MarkupLineInterpolated($"[blue][[INFO]] {message}[/]");
    }

    public static void LogSuccess(string message)
    {
        AnsiConsole.MarkupLineInterpolated($"[green][[INFO]] {message}[/]");
    }

    public static void WriteLine(string message)
    {
        AnsiConsole.WriteLine(message);
    }

    public static bool Confirm(string message)
    {
        return AnsiConsole.Confirm(Markup.Escape(message));
    }

    public static List<string> MultilineInput(string message)
    {
        AnsiConsole.MarkupLineInterpolated($"[yellow]{message}[/]");
        AnsiConsole.MarkupLine($"[green]Press enter on an empty line to finish[/]");

        List<string> lines = new();
        while (true)
        {
            var line = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(line))
            {
                break;
            }
            lines.Add(line);
        }
        return lines;
    }

    public static string? Input(string message)
    {
        AnsiConsole.MarkupLineInterpolated($"[yellow]{message}[/]");
        return Console.ReadLine();
    }

    public class PercentProgressBar
    {
        private TaskCompletionSource<double> progressBarTask = new();
        private TaskCompletionSource progressUpdated = new();
        private bool isFinished = false;
        private int lastPercent = 0;
        public PercentProgressBar(string task)
        {
            var prog = AnsiConsole.Progress();
            prog.AutoClear(true)
                .AutoRefresh(true)
                .Columns(new TaskDescriptionColumn(), new ProgressBarColumn(), new PercentageColumn(), new RemainingTimeColumn(), new SpinnerColumn())
                .StartAsync(async ctx =>
                {
                    var task1 = ctx.AddTask(task);
                    task1.MaxValue = 100;
                    isFinished = ctx.IsFinished;
                    while (!isFinished)
                    {
                        var newProgress = await progressBarTask.Task;

                        task1.Value = newProgress;

                        ctx.Refresh();
                        isFinished = ctx.IsFinished;
                        if (!isFinished)
                        {
                            progressBarTask = new TaskCompletionSource<double>();
                            progressUpdated.SetResult();
                        }
                    }

                    ctx.Refresh();
                    progressBarTask = new TaskCompletionSource<double>();
                    progressUpdated.SetResult();
                });
        }

        /// <summary>
        /// Not thread safe
        /// </summary>
        /// <param name="newProgressPercent"></param>
        /// <returns></returns>
        public async Task Update(double newProgressPercent)
        {
            if (isFinished)
            { return; }

            // avoid hammering console with updates
            int rounded = (int)Math.Round(newProgressPercent, 0);
            if (lastPercent >= rounded && (int)newProgressPercent != 100)
            { return; }

            lastPercent = newProgressPercent >= 100 ? 100 : rounded;

            progressUpdated = new();
            progressBarTask.SetResult(newProgressPercent);
            await progressUpdated.Task;
        }


    }



    public class FileCopyProgressBar
    {
        private TaskCompletionSource<double> progressBarTask = new();
        private TaskCompletionSource progressUpdated = new();
        private bool isFinished = false;
        private long lastRenderedBytesCopied = 0;
        private long bytesCopied = 0;
        private long totalBytes = 0;
        public FileCopyProgressBar(string task, long totalBytes)
        {
            this.totalBytes = totalBytes;
            var prog = AnsiConsole.Progress();
            prog.AutoClear(true)
                .AutoRefresh(true)
                .Columns(new TaskDescriptionColumn(), new ProgressBarColumn(), new PercentageColumn(), new BytesCopiedColumn(this), new RemainingTimeColumn(), new SpinnerColumn())
                .StartAsync(async ctx =>
                {
                    var task1 = ctx.AddTask(task);
                    task1.MaxValue = this.totalBytes;
                    isFinished = ctx.IsFinished;
                    while (!isFinished)
                    {
                        var newProgress = await progressBarTask.Task;

                        task1.Value = newProgress;

                        ctx.Refresh();
                        isFinished = ctx.IsFinished;
                        if (!isFinished)
                        {
                            progressBarTask = new TaskCompletionSource<double>();
                            progressUpdated.SetResult();
                        }
                    }

                    ctx.Refresh();
                    progressBarTask = new TaskCompletionSource<double>();
                    progressUpdated.SetResult();
                });
        }

        private SemaphoreSlim updateLock = new(1, 1);

        public async Task Update(long newTotalBytesCopied) => await Update(newTotalBytesCopied, true);
        private async Task Update(long newTotalBytesCopied, bool doLock = true)
        {
            if (isFinished)
            { return; }
            
            if (doLock)
            {
                await updateLock.WaitAsync();
            }

            try
            {
                // avoid hammering console with updates
                // only update every percent or every 8 mb, so if the file is large, we update for the remaining time to refresh quickly
                long bytesPerPercent = totalBytes / 100;
                long eightMb = 8 * 1024 * 1024;

                long updateThreshold = Math.Min(bytesPerPercent, eightMb);

                if (newTotalBytesCopied - lastRenderedBytesCopied < updateThreshold && newTotalBytesCopied != totalBytes)
                { return; }

                lastRenderedBytesCopied = newTotalBytesCopied;

                progressUpdated = new();
                progressBarTask.SetResult(newTotalBytesCopied);
                await progressUpdated.Task;
            }
            catch (System.Exception)
            {
                throw;
            }
            finally
            {
                if (doLock)
                {
                    updateLock.Release();
                }
            }
        }

        /// <summary>
        /// Not thread safe
        /// </summary>
        /// <param name="bytesCopied"></param>
        /// <returns></returns>
        public async Task Increment(long bytesCopied)
        {
            await updateLock.WaitAsync();
            try
            {
                this.bytesCopied += bytesCopied;
                await Update(this.bytesCopied, false);
            }
            finally
            {
                updateLock.Release();
            }
        }


        private class BytesCopiedColumn : ProgressColumn
        {
            private readonly FileCopyProgressBar parent;
            public BytesCopiedColumn(FileCopyProgressBar parent)
            {
                this.parent = parent;
            }
            private static readonly string[] units = ["B", "KB", "MB", "GB", "TB"];
            public override IRenderable Render(RenderOptions options, ProgressTask task, TimeSpan deltaTime)
            {
                double bytesCopied = parent.lastRenderedBytesCopied;
                double totalBytes = parent.totalBytes;
                int unitIndex = 0;
                while (totalBytes > 1024 && unitIndex < units.Length)
                {
                    totalBytes /= 1024;
                    unitIndex++;
                }

                bytesCopied /= Math.Pow(1024, unitIndex);

                var bytesCopiedString = $"{bytesCopied:N2} {units[unitIndex]}/{totalBytes:N2} {units[unitIndex]}";

                return new Markup(bytesCopiedString);
            }
        }


    }
}
