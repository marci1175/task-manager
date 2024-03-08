use std::time::Duration;

use chrono::Local;
use eframe::App;
use egui::Sense;
use egui_extras::{Column, TableBuilder};
use task_manager::{
    combine_bits, display_error_message, fetch_proc_name, filetime_to_systemtime, get_process_list, ProcessAttributes
};
#[derive(Clone, Debug, PartialEq)]
enum SortProcesses {
    Name(String),
    CpuUsage,
    RamUsage,
    DriveUsage,
    Pid,
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

    biggest_col_height: f32,

    #[serde(skip)]
    sort_processes: Option<SortProcesses>,
}

impl TaskManager {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        if let Some(storage) = cc.storage {
            return eframe::get_value(storage, eframe::APP_KEY).unwrap_or_default();
        }

        Default::default()
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

            sort_processes: None,
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
                });

                ui.menu_button("Search", |ui| {
                    if let Some(SortProcesses::Name(inner_string)) = self.sort_processes.as_mut() {
                        ui.text_edit_singleline(inner_string);
                    }

                    egui::ComboBox::from_id_source("Search")
                        .selected_text({
                            if let Some(search_parameter) = &self.sort_processes {
                                format!("{:?}", search_parameter)
                            } else {
                                format!("{:?}", self.sort_processes.clone())
                            }
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.sort_processes,
                                Some(SortProcesses::CpuUsage),
                                "Cpu Usage",
                            );
                            ui.selectable_value(
                                &mut self.sort_processes,
                                Some(SortProcesses::Name(String::new())),
                                "Name",
                            );
                            ui.selectable_value(
                                &mut self.sort_processes,
                                Some(SortProcesses::RamUsage),
                                "Ram Usage",
                            );
                            ui.selectable_value(
                                &mut self.sort_processes,
                                Some(SortProcesses::DriveUsage),
                                "Drive usage",
                            );
                            ui.selectable_value(
                                &mut self.sort_processes,
                                Some(SortProcesses::Pid),
                                "Process Id",
                            );
                        });
                });

                ui.label(format!(
                    "Process count: {}",
                    self.current_process_list.len()
                ));
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            TableBuilder::new(ui)
                .resizable(true)
                .striped(true)
                .columns(
                    Column::auto_with_initial_suggestion(ctx.available_rect().width() / 5.),
                    5,
                )
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

                        // //Fill out the rest of the ui
                        // ui.allocate_space(ui.available_size());
                    });
                })
                .body(|mut body| {
                    //Insert process flags here
                    for (index, proc_attributes) in self.current_process_list.iter().enumerate() {
                        body.row(25., |mut row| {
                            //proc_name
                            let col_height = row
                                .col(|ui| {
                                    ui.horizontal_centered(|ui| {
                                        ui.label(fetch_proc_name(proc_attributes.process.szExeFile))
                                    });
                                })
                                .0
                                .height();

                            if col_height > self.biggest_col_height {
                                self.biggest_col_height = col_height
                            };

                            //processor usage
                            row.col(|ui| {
                                ui.horizontal_centered(|ui| {
                                    //(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() / std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() - 1) as f64
                                    if let Some(last_proc_list) = self.last_process_list.get(index)
                                    {
                                        let usage = (proc_attributes.process_cpu_info.cpu_time_kernel + proc_attributes.process_cpu_info.cpu_time_user - last_proc_list.process_cpu_info.cpu_time_kernel + last_proc_list.process_cpu_info.cpu_time_user).as_secs_f64() / (chrono::Local::now().timestamp() as f64 / self.last_check_time.timestamp() as f64);

                                        /*(cur_time / prev_time) */
                                        ui.label(format!("{:.2}", usage));
                                    }

                                    // filetime_to_systemtime(proc_attributes.process_cpu_info);
                                });
                            });

                            //thread count
                            row.col(|ui| {
                                ui.horizontal_centered(|ui| {
                                    ui.label(format!("{}", proc_attributes.process.cntThreads))
                                });
                            });

                            //ram usage
                            row.col(|ui| {
                                ui.horizontal_centered(|ui| {
                                    //In bytes
                                    let memory_usage =
                                        proc_attributes.process_memory.WorkingSetSize;

                                    ui.label(format!("{}", memory_usage));
                                });
                            });

                            //process id
                            row.col(|ui| {
                                ui.horizontal_centered(|ui| {
                                    ui.label(format!("{}", proc_attributes.process.th32ProcessID))
                                });
                            });

                            //returns response
                            if row.response().interact(Sense::click()).clicked() {
                                println!("Fasz!");
                            }
                        });
                    }
                });
        });

        //Check for processes
        if self.last_check.elapsed() > Duration::from_secs(self.update_frequency) {
            self.last_check = std::time::Instant::now();

            self.last_check_time = chrono::Local::now();

            //Run the proc finding
            match get_process_list() {
                Ok(proc_list) => {
                    
                    if self.current_process_list.is_empty() {
                        self.last_process_list = proc_list.clone();
                    }
                    else {
                        self.last_process_list = self.current_process_list.clone();
                    }

                    self.current_process_list = proc_list;
                }
                Err(err) => {
                    dbg!(err.backtrace());
                    display_error_message(format!("{err}"), "Error");
                }
            }
        }

        //run 4 ever
        ctx.request_repaint();
    }
}
