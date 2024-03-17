use std::{fmt::Display, path::PathBuf, time::Duration};

use chrono::Local;
use eframe::App;
use egui::{vec2, Sense};
use egui_extras::{Column, TableBuilder};
use rfd::FileDialog;
use task_manager::{
    display_error_message, fetch_raw_string, get_priority_class_process, get_process_list,
    inject_dll_into_process, set_priority_class_process, terminate_process, ProcessAttributes,
};
use windows::Win32::System::Threading::{
    ABOVE_NORMAL_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS, HIGH_PRIORITY_CLASS,
    IDLE_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS, REALTIME_PRIORITY_CLASS,
};

#[derive(Clone, Debug, PartialEq)]
pub enum SortProcesses {
    CpuUsage,
    RamUsage,
    DriveUsage,
    Pid,
}

impl Display for SortProcesses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SortProcesses::CpuUsage => "CPU usage",
            SortProcesses::RamUsage => "RAM usage",
            SortProcesses::DriveUsage => "Drive usage",
            SortProcesses::Pid => "Process ID",
        })
    }
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
enum Unit {
    B,
    KB,
    MB,
    GB,
    TB,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct TaskManager {
    #[serde(skip)]
    current_process_list: Vec<ProcessAttributes>,

    #[serde(skip)]
    last_process_list: Vec<ProcessAttributes>,

    #[serde(skip)]
    last_check_time: chrono::DateTime<Local>,

    #[serde(skip)]
    last_check: std::time::Instant,

    update_frequency: u64,

    processor_usage: f64,

    biggest_col_height: f32,

    #[serde(skip)]
    sort_processes: Option<SortProcesses>,

    string_buffer_search: String,

    memory_unit: Unit,
}

impl TaskManager {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        if let Some(storage) = cc.storage {
            return eframe::get_value(storage, eframe::APP_KEY).unwrap_or_default();
        }

        Default::default()
    }

    fn extract_processes(&mut self) {
        self.last_check = std::time::Instant::now();

        self.last_check_time = chrono::Local::now();

        self.processor_usage = 0.;

        //Run the proc finding
        match get_process_list() {
            Ok(proc_list) => {
                if self.current_process_list.is_empty() {
                    self.last_process_list = proc_list.clone();
                } else {
                    self.last_process_list = self.current_process_list.clone();
                }

                //filter / sort depending on SortProcesses (self.sort_processes) else just load in the raw proc list
                if let Some(sort_by) = self.sort_processes.clone() {
                    self.filter_processes(sort_by);
                } else {
                    self.current_process_list = proc_list;
                }
            }
            Err(err) => {
                dbg!(err.backtrace());
                display_error_message(format!("{err}"), "Error");
            }
        }
    }

    fn filter_processes(&mut self, filter: SortProcesses) {
        match filter {
            SortProcesses::CpuUsage => {
                self.current_process_list
                    .sort_by_key(|key| key.processor_usage.floor() as i64);
            }
            SortProcesses::RamUsage => {
                self.current_process_list
                    .sort_by_key(|key| key.process_memory.WorkingSetSize);
            }
            SortProcesses::DriveUsage => {}
            SortProcesses::Pid => {
                self.current_process_list
                    .sort_by_key(|key| key.process.th32ProcessID);
            }
        }
    }
}

impl Default for TaskManager {
    fn default() -> Self {
        Self {
            current_process_list: Vec::new(),
            last_process_list: Vec::new(),

            last_check_time: chrono::Local::now(),
            last_check: std::time::Instant::now(),

            update_frequency: 3,

            biggest_col_height: 400.,

            processor_usage: 0.,

            sort_processes: None,
            string_buffer_search: String::new(),
            memory_unit: Unit::MB,
        }
    }
}

impl App for TaskManager {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal_centered(|ui| {
                ui.menu_button("Settings", |ui| {
                    ui.label("Process check delay (Seconds)");
                    ui.add(egui::widgets::Slider::new(
                        &mut self.update_frequency,
                        1..=30,
                    ));

                    ui.horizontal(|ui| {
                        ui.label("Memory unit");

                        let _combobox = egui::ComboBox::from_id_source("Memory unit")
                            .selected_text(format!("{:?}", self.memory_unit))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.memory_unit, Unit::B, "B");
                                ui.selectable_value(&mut self.memory_unit, Unit::KB, "KB");
                                ui.selectable_value(&mut self.memory_unit, Unit::MB, "MB");
                                ui.selectable_value(&mut self.memory_unit, Unit::GB, "GB");
                                ui.selectable_value(&mut self.memory_unit, Unit::TB, "TB");
                            });

                        ui.allocate_space(vec2(0., 120.));
                    });
                });

                ui.menu_button("Sort", |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Sort parameters");

                        let search = egui::ComboBox::from_id_source("Sort")
                            .selected_text({
                                if let Some(search_parameter) = &self.sort_processes {
                                    format!("{}", search_parameter)
                                } else {
                                    format!("{:?}", None::<()>)
                                }
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut self.sort_processes, None, "None")
                                    .clicked()
                                    || ui
                                        .selectable_value(
                                            &mut self.sort_processes,
                                            Some(SortProcesses::CpuUsage),
                                            "CPU Usage",
                                        )
                                        .clicked()
                                    || ui
                                        .selectable_value(
                                            &mut self.sort_processes,
                                            Some(SortProcesses::RamUsage),
                                            "RAM Usage",
                                        )
                                        .clicked()
                                    || ui
                                        .selectable_value(
                                            &mut self.sort_processes,
                                            Some(SortProcesses::DriveUsage),
                                            "Drive usage",
                                        )
                                        .clicked()
                                    || ui
                                        .selectable_value(
                                            &mut self.sort_processes,
                                            Some(SortProcesses::Pid),
                                            "Process ID",
                                        )
                                        .clicked()
                            });

                        //Check for interaction for faster refresh of the filtered processed
                        if let Some(inner) = search.inner {
                            if inner {
                                self.extract_processes();
                            }
                        }

                        ui.allocate_space(vec2(0., 140.));
                    });
                });

                ui.label(format!(
                    "Process count: {} | Processor usage: {}%",
                    self.current_process_list.len(),
                    self.processor_usage
                ));

                ui.add(
                    egui::TextEdit::singleline(&mut self.string_buffer_search)
                        .hint_text("Start typing PID or process name"),
                );
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            TableBuilder::new(ui)
                .resizable(true)
                .auto_shrink([false, false])
                .striped(true)
                .columns(Column::remainder().at_most(ctx.available_rect().width()), 5)
                .header(25., |mut row| {
                    //Main rows (ram usage, etc)
                    row.col(|ui| {
                        ui.label("Process name");
                    });
                    row.col(|ui| {
                        ui.label("Processor usage");
                    });
                    row.col(|ui| {
                        ui.label("Thread count");
                    });
                    row.col(|ui| {
                        ui.label("Ram usage");
                    });
                    row.col(|ui| {
                        ui.label("Process ID");
                    });
                })
                .body(|mut body| {
                    //Insert process flags here
                    for (index, proc_attributes) in self.current_process_list.iter_mut().enumerate()
                    {
                        //Fetch process name so we, can check for it in filtering
                        let process_name = fetch_raw_string(proc_attributes.process.szExeFile);

                        //Check for process name, and if the process's name contains the filter
                        if !proc_attributes
                            .process
                            .th32ProcessID
                            .to_string()
                            .contains(self.string_buffer_search.trim())
                            && !process_name.contains(self.string_buffer_search.trim())
                        {
                            //Continue with next entry
                            continue;
                        }

                        //Create row
                        body.row(25., |mut row| {
                            //proc_name
                            let proc_name = row.col(|ui| {
                                ui.horizontal_centered(|ui| {
                                    ui.label(process_name);
                                });
                            });

                            if proc_name.0.height() > self.biggest_col_height {
                                self.biggest_col_height = proc_name.0.height()
                            };

                            //processor usage DO TOUCH
                            let proc_usage = row.col(|ui| {
                                ui.horizontal_centered(|ui| {
                                    if let Some(last_proc_list) = self.last_process_list.get(index)
                                    {
                                        //Check if this process is exiting (wtf MS), for some unkown reason last_proc is bigger when terminating / exiting, therefor causes a crash
                                        if (proc_attributes.process_cpu_info.cpu_time_kernel
                                            + proc_attributes.process_cpu_info.cpu_time_user)
                                            >= (last_proc_list.process_cpu_info.cpu_time_kernel
                                                + last_proc_list.process_cpu_info.cpu_time_user)
                                        {
                                            let usage = (proc_attributes
                                                .process_cpu_info
                                                .cpu_time_kernel
                                                + proc_attributes.process_cpu_info.cpu_time_user
                                                - last_proc_list.process_cpu_info.cpu_time_kernel
                                                + last_proc_list.process_cpu_info.cpu_time_user)
                                                .as_secs_f64()
                                                / (chrono::Local::now().timestamp() as f64
                                                    / self.last_check_time.timestamp() as f64);

                                            proc_attributes.processor_usage = usage;

                                            /*(cur_time / prev_time) */
                                            ui.label(format!("{:.2} %", usage));
                                        }
                                    }

                                    // filetime_to_systemtime(proc_attributes.process_cpu_info);
                                });
                            });

                            //thread count
                            let thread_count = row.col(|ui| {
                                ui.horizontal_centered(|ui| {
                                    ui.label(format!("{}", proc_attributes.process.cntThreads))
                                });
                            });

                            //ram usage
                            let ram_usage = row.col(|ui| {
                                ui.horizontal_centered(|ui| {
                                    //In bytes
                                    let memory_usage =
                                        proc_attributes.process_memory.WorkingSetSize;

                                    ui.label(match self.memory_unit {
                                        Unit::B => format!("{} B", memory_usage),
                                        Unit::KB => format!("{:.1} KB", memory_usage / 1024),
                                        Unit::MB => {
                                            format!(
                                                "{:.2} MB",
                                                memory_usage as f32 / 1024_f32.powf(2.)
                                            )
                                        }
                                        Unit::GB => {
                                            format!(
                                                "{:.3} GB",
                                                memory_usage as f32 / 1024_f32.powf(3.)
                                            )
                                        }
                                        Unit::TB => {
                                            format!(
                                                "{:.5} TB",
                                                memory_usage as f32 / 1024_f32.powf(4.)
                                            )
                                        }
                                    });
                                });
                            });

                            //process id
                            let proc_id = row.col(|ui| {
                                ui.horizontal_centered(|ui| {
                                    ui.label(format!("{}", proc_attributes.process.th32ProcessID))
                                });
                            });

                            if proc_id.1.clicked() {
                                ctx.copy_text(proc_attributes.process.th32ProcessID.to_string());
                            }

                            proc_name.1.context_menu(|ui| {
                                ui.label("Process settings");

                                ui.separator();

                                if ui.button("Terminate process").clicked() {
                                    if let Err(err) =
                                        terminate_process(proc_attributes.process.th32ProcessID)
                                    {
                                        display_error_message(err, "Error");
                                    };
                                }

                                if ui.button("Terminate parent process").clicked() {
                                    if let Err(err) = terminate_process(
                                        proc_attributes.process.th32ParentProcessID,
                                    ) {
                                        display_error_message(err, "Error");
                                    };
                                }

                                ui.separator();

                                if ui.button("Copy process path").clicked() {
                                    ctx.copy_text(fetch_raw_string(
                                        proc_attributes.module.szExePath,
                                    ))
                                }

                                if ui.button("Show file location").clicked() {
                                    let path = fetch_raw_string(proc_attributes.module.szExePath);

                                    //Strip path from nul bytes
                                    let stripped_path =
                                        PathBuf::from(path.trim_matches(|c| c == '\0'));

                                    match std::process::Command::new("explorer")
                                        .arg("/select,")
                                        .arg(stripped_path.to_string_lossy().to_string())
                                        .spawn()
                                    {
                                        Ok(_) => {}
                                        Err(err) => {
                                            display_error_message(err, "Error");
                                        }
                                    }
                                }

                                ui.separator();

                                //Set priorityy class
                                ui.menu_button("Set priority class", |ui| {
                                    if let Ok(priority) = get_priority_class_process(
                                        proc_attributes.process.th32ProcessID,
                                    ) {
                                        ui.label(format!(
                                            "Current priority: {}",
                                            match priority {
                                                REALTIME_PRIORITY_CLASS => "Realtime",
                                                HIGH_PRIORITY_CLASS => "High",
                                                ABOVE_NORMAL_PRIORITY_CLASS => "Above normal",
                                                NORMAL_PRIORITY_CLASS => "Normal",
                                                BELOW_NORMAL_PRIORITY_CLASS => "Below normal",
                                                IDLE_PRIORITY_CLASS => "Idle",
                                                _ => "Unknown",
                                            }
                                        ));
                                    }
                                    if ui.button("Idle").clicked() {
                                        if let Err(err) = set_priority_class_process(
                                            proc_attributes.process.th32ProcessID,
                                            IDLE_PRIORITY_CLASS,
                                        ) {
                                            display_error_message(err, "Error");
                                        }
                                    };
                                    if ui.button("Below normal").clicked() {
                                        if let Err(err) = set_priority_class_process(
                                            proc_attributes.process.th32ProcessID,
                                            BELOW_NORMAL_PRIORITY_CLASS,
                                        ) {
                                            display_error_message(err, "Error");
                                        }
                                    };
                                    if ui.button("Normal").clicked() {
                                        if let Err(err) = set_priority_class_process(
                                            proc_attributes.process.th32ProcessID,
                                            NORMAL_PRIORITY_CLASS,
                                        ) {
                                            display_error_message(err, "Error");
                                        }
                                    };
                                    if ui.button("Above normal").clicked() {
                                        if let Err(err) = set_priority_class_process(
                                            proc_attributes.process.th32ProcessID,
                                            ABOVE_NORMAL_PRIORITY_CLASS,
                                        ) {
                                            display_error_message(err, "Error");
                                        }
                                    };
                                    if ui.button("High").clicked() {
                                        if let Err(err) = set_priority_class_process(
                                            proc_attributes.process.th32ProcessID,
                                            HIGH_PRIORITY_CLASS,
                                        ) {
                                            display_error_message(err, "Error");
                                        }
                                    };
                                    if ui.button("Realtime (Administrator privileges)").clicked() {
                                        if let Err(err) = set_priority_class_process(
                                            proc_attributes.process.th32ProcessID,
                                            REALTIME_PRIORITY_CLASS,
                                        ) {
                                            display_error_message(err, "Error");
                                        }
                                    };
                                });

                                ui.separator();

                                if ui.button("Inject DLL").clicked() {
                                    let path_to_dll = FileDialog::new()
                                        .set_title("Select DLL")
                                        .add_filter("Dynamic load library", &["dll"])
                                        .pick_file();

                                    if let Some(path) = path_to_dll {
                                        if let Err(err) = inject_dll_into_process(
                                            proc_attributes.process.th32ProcessID,
                                            path,
                                        ) {
                                            display_error_message(err, "Error");
                                        };
                                    }
                                };

                                ui.separator();

                                ui.label(format!(
                                    "Parent PID: {}",
                                    proc_attributes.process.th32ParentProcessID
                                ));
                            });

                            proc_id.1.on_hover_text_at_pointer("Left click top copy");

                            proc_name
                                .1
                                .on_hover_text_at_pointer("Right click for more options");
                        });
                    }
                });
        });

        //Check for processes
        if self.last_check.elapsed() > Duration::from_secs(self.update_frequency) {
            self.extract_processes();
        }

        //run 4 ever
        ctx.request_repaint();
    }

    //Persistence
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, self);
    }
}
